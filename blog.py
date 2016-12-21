import hashlib
import hmac
import os
import random
import string
import time
import re
from string import letters
from user import User
from post import Post
from like import Like
import myHelper

import jinja2
import webapp2
from google.appengine.ext import db


## Random Secret Key
secret = ''.join(
    [random.choice(string.ascii_letters + string.digits) for n in xrange(32)])

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


#### Basic handler for blog. Handles basic and frequently used functions

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return myHelper.jinja_render_str(template, **params)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header(
            'Set-Cookie',
            'user_id=; Path=/')

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


#### Front Page of Blog - shows all posts

class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery(
            "select * from Post order by created desc limit 10")
        self.render('front.html', posts=posts)


#### Individual Post Page - shows single post based on id in URL.

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        comments = db.GqlQuery(
            "select * from Comment where ancestor is :1 order by created desc limit 10",
            key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post, comments=comments)


#### If the user is signed in, allow for the creation of a new post

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.render("login-form.html")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject,
                     content=content, user_id=self.user.key().id())
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "Post must have 'Title' and 'Content'."
            self.render("newpost.html", subject=subject,
                        content=content, error=error)


#### Validation for username, password and email

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")

def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")

def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

def valid_email(email):
    return not email or EMAIL_RE.match(email)


#### Handles the signup page, shows error if the fields
#### do not match the validation's above.

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "Sorry, that's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "Sorry, that's not a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Sorry, your passwords do not match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "Sorry, that's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self):
        self.redirect('/blog/welcome?username=' + self.username)


#### Create new user for blog

class Register(Signup):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user name already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


#### Log's out user

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


#### Handles login for blog

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid Username or Password'
            self.render('login-form.html', error=msg)


#### Welcome page after a user successfully logs in

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('/blog/signup')


#### Delete's post based on id in url

class Delete(BlogHandler):
    def get(self, post_id, post_user_id):
        if self.user and self.user.key().id() == int(post_user_id):
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post.delete()

            self.redirect('/blog')

        else:
            self.redirect('/login')


#### Allows the user of the post to edit page.
#### If they are not the user, display warning.

class EditPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user and self.user.key().id() == post.user_id:
            self.render('editpost.html', subject=post.subject,
                        content=post.content, post_id=post_id)
        else:
            self.redirect('/login')

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if self.user and self.user.key().id() == post.user_id:
            subject = self.request.get("subject")
            content = self.request.get("content")
            if subject and content:
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/blog/%s' % str(post.key().id()))
            else:
                error = "subject and content, please!"
                self.render("newpost.html", subject=subject,
                            content=content, error=error)
        else:
            self.redirect('/blog')


#### Allows logged in users to like others posts -
#### error ir you attempt to like your own

class LikePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user and self.user.key().id() == post.user_id:
            self.write("<h1>Sorry, You cannot like your own post!</h1>")
        elif not self.user:
            self.redirect('/login')
        else:
            l = Like.all().filter('user_id =', self.user.key().id()
                                  ).filter('post_id =', post.key().id()).get()

            if l:
                self.redirect('/blog/' + str(post.key().id()))
            else:
                like = Like(parent=key, user_id=self.user.key().id(),
                            post_id=post.key().id())
                post.likes += 1

                like.put()
                post.put()

                self.redirect('/blog/' + str(post.key().id()))


#### Allows logged in users to remove their like - error ir you attempt to remove your own like

class UnlikePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user and self.user.key().id() == post.user_id:
            self.write(
                "<h1>Sorry, You are not allowed to dislike your own post!</h1>")
        elif not self.user:
            self.redirect('/login')
        else:
            l = Like.all().filter('user_id =', self.user.key().id()
                                  ).filter('post_id =', post.key().id()).get()

            if l:
                l.delete()
                post.likes -= 1
                post.put()

                self.redirect('/blog/' + str(post.key().id()))
            else:
                self.redirect('/blog/' + str(post.key().id()))

class Comment(db.Model):
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user_id = db.IntegerProperty(required=True)


#### Allows logged in users to comment on others posts

class AddComment(BlogHandler):
    def get(self, post_id, user_id):
        self.render("addcomment.html")

    def post(self, post_id, user_id):
        if not self.user:
            return self.redirect('/login')

        user = self.user
        content = self.request.get('content')

        if content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            c = Comment(parent=key, user_id=int(user_id), content=content)
            c.put()
            self.redirect('/blog/' + post_id)
        else:
            error = "Comment must have content."
            self.render("addcomment.html",
                        content=content, error=error)


#### Allows logged in users to delete their own comment on others posts

class DeleteComment(BlogHandler):
    def get(self, post_id, post_user_id, comment_id):

        if self.user and self.user.key().id() == int(post_user_id):
            post_key = db.Key.from_path('Post', int(post_id),
                                        parent=blog_key())
            key = db.Key.from_path('Comment', int(comment_id), parent=post_key)
            comment = db.get(key)
            comment.delete()

            self.redirect('/blog/' + post_id)
        else:
            self.redirect('/blog/' + post_id)


#### Allows logged in users to edit their comment on others posts

class EditComment(BlogHandler):
    def get(self, post_id, post_user_id, comment_id):
        if self.user and self.user.key().id() == int(post_user_id):
            post_key = db.Key.from_path('Post', int(post_id),
                                        parent=blog_key())
            key = db.Key.from_path('Comment', int(comment_id), parent=post_key)
            comment = db.get(key)
            self.render('editcomment.html', content=comment.content)
        else:
            self.redirect('/blog/' + post_id)


    def post(self, post_id, post_user_id, comment_id):
        if not self.user:
            self.write(
                "<h1>You do not have permission to delete this comment.</h1>")

        user = self.user
        content = self.request.get('content')

        if content:
            post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            key = db.Key.from_path('Comment', int(comment_id), parent=post_key)
            comment = db.get(key)
            comment.content = content
            comment.put()
            self.redirect('/blog/' + post_id)
        else:
            error = "Edited comment must have content."
            self.render("editcomment.html",
                        content=content, error=error)


#### URL Configs
# @formatter:off
app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/blog/signup', Signup),
                               ('/blog/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/signup', Register),
                               ('/logout', Logout),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/delete/([0-9]+)/([0-9]+)', Delete),
                               ('/blog/([0-9]+)/edit', EditPost),
                               ('/blog/([0-9]+)/like', LikePost),
                               ('/blog/([0-9]+)/unlike', UnlikePost),
                               ('/blog/([0-9]+)/([0-9]+)/addcomment', AddComment),
                               ('/blog/([0-9]+)/([0-9]+)/([''0-9]+)/deletecomment',DeleteComment),
                               ('/blog/([0-9]+)/([0-9]+)/([0-9]+)/editcomment',EditComment)
                               ],
                              debug=True)
# @formatter:on
