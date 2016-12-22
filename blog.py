import hmac
import random
import re
import string


import webapp2
from google.appengine.ext import db

import myHelper
from like import Like
from post import Post
from user import User
from comment import Comment

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
    # Checks if the user is logged in
    def isLoggedIn(self):
        cookie = self.request.cookies.get('user_id')
        if cookie and check_secure_val(cookie):
            return cookie.split("|")[0]

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


#### Front Page of Blog - shows all posts limited
#### to 10 newest in descending order

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


#### Handles login for blog

class Login(BlogHandler):
    def get(self):
        if self.isLoggedIn():
            self.render("error.html", error="You are already logged in!")
        else:
            self.render("login-form.html")

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

#### Log's out user

class Logout(BlogHandler):
    def get(self):
        if self.isLoggedIn():
            self.logout()
            self.redirect('/blog')
        else:
            self.render("error.html", error = "You have to be logged in to log out!")


#### Welcome page after a user successfully logs in

class Welcome(BlogHandler):
    def get(self):
        username = self.isLoggedIn()
        if username:
            self.render('welcome.html', isLoggedIn = True, username=username)
        else:
            self.redirect('/blog/signup')


#### If the user is signed in, allow for the creation of a new post

class NewPost(BlogHandler):
    def get(self):
        if self.isLoggedIn():
            self.render("newpost.html", isLoggedIn=True)
        else:
            self.render("error.html", error = "You must be logged in to create a post.")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        username = self.isLoggedIn()
        if subject and content:
            if username:
                p = Post(parent=blog_key(), subject=subject,
                         content=content, user_id=self.user.key().id())
                p.put()
                self.redirect('/blog/%s' % str(p.key().id()))
            else:
                self.redirect('/blog/signup')
        else:
            error = "Post must have 'Title' and 'Content'."
            self.render("newpost.html", isLoggedIn=True, subject=subject, content=content, error=error)


#### Allows the user of the post to edit page.
#### If they are not the user, display warning.

class EditPost(BlogHandler):
    def get(self, post_id):
        username = self.isLoggedIn()
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if username:
            if post.user_id == self.user.key().id():
                self.render("editpost.html", isLoggedIn = True, subject=post.subject, content=post.content)
            else:
                self.render("error.html", error = "You do not have required permission to edit this post!")
        else:
            self.redirect("/blog/signup")

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % post_id)
        else:
            error = "Post must have subject and content!"
            self.render("editpost.html", subject=subject,
                        content=content, error=error)


#### Delete's post based on id in url

class Delete(BlogHandler):
    def get(self, post_id, post_user_id):
        username = self.isLoggedIn()
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if username:
            if post.user_id == self.user.key().id():
                post.delete()
                self.redirect('/blog')
            else:
                self.render("error.html", error="You do not have required permission to delete this post!")
        else:
            self.render("error.html",
                        error="You must be logged in to delete this post!")


#### Allows logged in users to like others posts -
#### Cannot like your own post or others without being logged in

class LikePost(BlogHandler):
    def get(self, post_id):
        username = self.isLoggedIn()
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if username:
            if self.user and self.user.key().id() == post.user_id:
                self.render("error.html", error="You cannot like your own post!")
            else:
                l = Like.all().filter('user_id =', self.user.key().id()
                                      ).filter('post_id =',
                                               post.key().id()).get()
                if l:
                    self.redirect('/blog/' + str(post.key().id()))
                else:
                    like = Like(parent=key, user_id=self.user.key().id(),
                                post_id=post.key().id())
                    post.likes += 1
                    like.put()
                    post.put()
                    self.redirect('/blog/' + str(post.key().id()))
        else:
            self.render("error.html", error="You must be logged in to 'like' a post.")


#### Allows logged in users to remove their like
#### Cannot dislike your own post or others without being logged in

class UnlikePost(BlogHandler):
    def get(self, post_id):
        username = self.isLoggedIn()
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if username:
            if self.user and self.user.key().id() == post.user_id:
                self.render("error.html",
                            error="You cannot dislike your own post!")
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
        else:
            self.render("error.html",
                        error="You must be logged in to 'like/dislike' a post.")


#### Allows logged in users to comment on others posts

class AddComment(BlogHandler):
    def get(self, post_id, user_id):
        username = self.isLoggedIn()
        post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(post_key)
        if username:
            self.render("addcomment.html", isLoggedIn=True, post=post)
        else:
            self.render("error.html", error="You have to be logged in to add a comment.")

    def post(self, post_id, user_id):
        content = self.request.get("content")
        username = self.isLoggedIn()
        # post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        # post = db.get(post_key)
        if content:
            if username:
                comment = Comment(parent=key, user_id=int(user_id), content=content)
                comment.put()
                self.redirect('/blog/' + post_id)
            else:
                self.render("error.html", error="You must be logged in to add a comment.")
        else:
            error = "Comment must have content!"
            self.render("addcomment.html",
                        content=content, error=error)


#### Allows logged in users to delete their own comment on others posts

class DeleteComment(BlogHandler):
    def get(self, post_id, post_user_id, comment_id):
        username = self.isLoggedIn()
        post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        key = db.Key.from_path('Comment', int(comment_id), parent=post_key)
        comment = db.get(key)
        if username:
            if self.user and self.user.key().id() == int(post_user_id):
                comment.delete()
                self.redirect('/blog/' + post_id)
            else:
                self.render("error.html", error="You do not have the required permission to delete this comment.")
        else:
            self.render("error.html", error="Please sign in to delete a comment.")


#### Allows logged in users to edit their comment on others posts

class EditComment(BlogHandler):
    def get(self, post_id, post_user_id, comment_id):
        username = self.isLoggedIn()
        post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        key = db.Key.from_path('Comment', int(comment_id), parent=post_key)
        comment = db.get(key)
        post = db.get(post_key)
        if username:
            if self.user and self.user.key().id() == int(post_user_id):
                self.render("editcomment.html", isLoggedIn = True, post=post, content=comment.content)
            else:
                self.render("error.html", error="You cannot edit someone else's comment!")
        else:
            self.render("error.html", error="You must be logged in to edit a comment.")

    def post(self, post_id, post_user_id, comment_id):
        username = self.isLoggedIn()
        content = self.request.get("content")
        post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        key = db.Key.from_path('Comment', int(comment_id), parent=post_key)
        comment = db.get(key)
        if content:
            if username:
                if self.user and self.user.key().id() == int(post_user_id):
                     comment.content = content
                     comment.put()
                     self.redirect('/blog/' + post_id)
                else:
                    self.render("error.html", error="You do not have permission to edit someone's comment!")
            else:
                self.render("error.html", error="You must sign in to edit a comment")
        else:
            error = "Edited comment must have content."
            self.render("editcomment.html", content=content, error=error)


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
