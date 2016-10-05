from __future__ import unicode_literals
import datetime
from django.utils import timezone

from django.db import models
from django.utils.encoding import python_2_unicode_compatible

# Create your models here.



class Question(models.Model):
    question_text = models.CharField(max_length=200)
    pub_date = models.DateTimeField('date published')

    def was_published_recently(self):
        return self.pub_date >= timezone.now() - datetime.timedelta(days=1)
    def __unicode__(self):
	    return self.question_text


#@python_2_unicode_compatible
class Choice(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    choice_text = models.CharField(max_length=200)
    votes = models.IntegerField(default=0)
    def __unicode__(self):
        return self.choice_text

class User(models.Model):
    login = models.CharField(unique=True, max_length=20)
    password = models.CharField(max_length=20)
    name = models.CharField(max_length=20)
    student = models.BooleanField()

class Session(models.Model):
    key = models.CharField(unique=True, max_length=20)
    user = models.ForeignKey(User)
    expires = models.DateTimeField()



	
