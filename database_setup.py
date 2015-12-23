# All of this is taken from Lesson 1 of Full Stack Foundations
import sys
from sqlalchemy import Column, ForeignKey, Integer, String, Text, DateTime, \
    UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
import datetime

Base = declarative_base()

# created_date below is from here: http://stackoverflow.com/a/13370382


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    picture = Column(String(255))
    email = Column(String(255), nullable=False, unique=True)
    created_date = Column(DateTime, default=datetime.datetime.utcnow)


class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False, unique=True)
    created_date = Column(DateTime, default=datetime.datetime.utcnow)

    @property
    def serialize(self):
        # Returns a serialized version of this object which helps us convert
        # To JSON
        return {
            'id': self.id,
            'name': self.name,
            'created_date': self.created_date
        }


class Item(Base):
    __tablename__ = 'item'
    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False)
    picture = Column(String(200))
    owner_id = Column(Integer, ForeignKey('user.id'))
    description = Column(Text)
    user = relationship(User)
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    created_date = Column(DateTime, default=datetime.datetime.utcnow)
    __table_args__ = (UniqueConstraint('name', 'category_id',
                                       name='_item_cat_uc'),)
    # Code to specify table args for unique constraint from:
    # http://stackoverflow.com/a/10061143

    @property
    def serialize(self):
        # Returns a serialized version of this object which helps us convert
        # To JSON
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'picture': self.picture,
            'category_name': self.category.name,
            'created_date': self.created_date
        }

engine = create_engine('sqlite:///catalog.db')
Base.metadata.create_all(engine)
