
# from flask_sqlalchemy import SQLAlchemy
# from flask_login import UserMixin

# db = SQLAlchemy()

# class User(UserMixin, db.Model):
#     __tablename__ = 'user'
#     id = db.Column(db.Integer, primary_key=True)
#     fname = db.Column(db.String(50), nullable=False)
#     lname = db.Column(db.String(50), nullable=False)
#     email = db.Column(db.String(100), nullable=False, unique=True)
#     password = db.Column(db.String(100), nullable=False)
#     posts = db.relationship('Post', backref='author', lazy=True)

#     def __repr__(self):
#         return f"User('{self.fname}', '{self.lname}', '{self.email}')"
    
# class Post(db.Model):
#     __tablename__ = 'post'
#     id = db.Column(db.Integer, primary_key=True)
#     title = db.Column(db.String(100), nullable=False)
#     content = db.Column(db.Text, nullable=False)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

#     def __repr__(self):
#         return f"Post('{self.title}', '{self.content}')"
