from django import forms

class LoginForm(forms.Form):
	login = forms.CharField(max_length=20)
	password = forms.CharField(widget=forms.PasswordInput())

	def save(self):
		post = User(**self.cleaned_data)
		post.save()
		return post