from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse, HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.template import RequestContext, loader
from .models import Question, Choice, User, Session
from .forms import LoginForm
import hashlib, uuid
import string
import random

# Create your views here.'
from django.http import HttpResponse

def detail(request, question_id):
    try:
        question = Question.objects.get(pk=question_id)
    except Question.DoesNotExist:
        raise Http404("Question does not exist")
    return render(request, 'polls/detail.html', {'question': question})

def results(request, question_id):
    question = get_object_or_404(Question, pk=question_id)
    return render(request, 'polls/results.html', {'question': question})

def vote(request, question_id):
    question = get_object_or_404(Question, pk=question_id)
    try:
        selected_choice = question.choice_set.get(pk=request.POST['choice'])
    except (KeyError, Choice.DoesNotExist):
        # Redisplay the question voting form.
        return render(request, 'polls/detail.html', {
            'question': question,
            'error_message': "You didn't select a choice!",
        })
    else:
        selected_choice.votes += 1
        selected_choice.save()
        # Always return an HttpResponseRedirect after successfully dealing
        # with POST data. This prevents data from being posted twice if a
        # user hits the Back button.
        return HttpResponseRedirect(reverse('polls:results', args=(question.id,)))

def index(request):
    latest_question_list = Question.objects.order_by('-pub_date')[:5]
    template = loader.get_template('polls/index.html')
    context = RequestContext(request, {
        'latest_question_list': latest_question_list,
    })
    return HttpResponse(template.render(context))
'''
def login(request):
	error = ''
	if request.method == 'POST':
		login = request.POST.get('login')
		password = request.POST.get('password')
		url = request.POST.get('continue', '/')
		sessid = do_login(login, password)
		if sessid:
			response = HttpResponseRedirect(url)
			response.set_cookie('sessid', sessid,
			domain='127.0.0.1:8000', httponly=True,
			expires = datetime.now()+timedelta(days=5)
			)
			return response
		else:
			error = 'Wrong login/pass'
	return render(request, 'login.html', {'error': error })

def do_login(login, password):
	try:
		user = User.objects.get(login=login)
	except User.DoesNotExist:
		return None
	hashed_pass = salt_and_hash(password)
	if user.password != hashed_pass
		return None
	session = Session()
	session.key = generate_long_random_key(20)
	session.user = user
	session.expires = datetime.now() + timedelta(days=5)
	session.save()
	return session.key	

def salt_and_hash(pass):
	salt = uuid.uuid4().hex
	return hashlib.sha512(pass + salt).hexdigest()

def generate_long_random_key(size=6, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
	return ''.join(random.choice(chars) for _ in range(size))
'''

def login(request):
	error_message = ''
	if request.method == "GET":
		form = LoginForm()
		return render(request, 'polls/login.html', {'form': form})