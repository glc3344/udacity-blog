from google.appengine.ext import db


from user import users_key
import myHelper


#### Create's Post model for database - includes post model functions
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(default=0)
    user_id = db.IntegerProperty(required=True)

    def render(self, current_user_id):
        key = db.Key.from_path('User', int(self.user_id), parent=users_key())
        user = db.get(key)
        self._render_text = self.content.replace('\n', '<br>')
        return myHelper.jinja_render_str("post.html", p=self, current_user_id=current_user_id,
                          author=user.name)

    @classmethod
    def by_id(cls, uid):
        return Post.get_by_id(uid, parent = blog_key())
