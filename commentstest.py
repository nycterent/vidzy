#!/bin/env python

from datetime import datetime
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:1234@localhost:3306/vidzy'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

Base = declarative_base()

db = SQLAlchemy(app)

engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])

Session = sessionmaker(bind=engine)
session = Session()

class Comment(Base):
    __tablename__ = 'vidcomments'
    _N = 6

    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(140))
    author = db.Column(db.String(32))
    timestamp = db.Column(db.DateTime(), default=datetime.utcnow, index=True)
    path = db.Column(db.Text(400), index=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('vidcomments.id'))
    replies = db.relationship(
        'Comment', backref=db.backref('parent', remote_side=[id]),
        lazy='dynamic')

    def save(self):
        db.session.add(self)
        db.session.commit()
        prefix = self.parent.path + '.' if self.parent else ''
        self.path = prefix + '{:0{}d}'.format(self.id, self._N)
        db.session.commit()

    def level(self):
        return len(self.path) // self._N - 1

with app.app_context():
    Base.metadata.create_all(engine)

c1 = Comment(text='hello1', author='alice')
c2 = Comment(text='hello2', author='bob')
c11 = Comment(text='reply11', author='bob', parent=c1)
c111 = Comment(text='reply111', author='susan', parent=c11)
c21 = Comment(text='reply21', author='alice', parent=c2)
c12 = Comment(text='reply12', author='susan', parent=c1)

with app.app_context():
    for comment in [c1, c2, c11, c12, c111, c21]:
        comment.save()

for comment in session.query(Comment).order_by(Comment.path):
    print('{}{}: {}'.format('  ' * comment.level(), comment.author, comment.text))