from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import db, User, Feedback
from flask_bcrypt import Bcrypt
from forms import LoginForm, RegisterForm, FeedbackForm

app=Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql:///flasklogin"
app.config['SECRET_KEY']='abc'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config['SQLALCHEMY_ECHO'] = True
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
bcrypt=Bcrypt(app)

toolbar = DebugToolbarExtension(app)

db.init_app(app)

if __name__ == '__main__':
    app.run(debug=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form=RegisterForm()
    if form.validate_on_submit():
        hashed_pwd=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user=User(username=form.username.data, password=hashed_pwd, email=form.email.data, first_name=form.first_name.data, last_name=form.last_name.data)
        db.session.add(user)
        db.session.commit()
        session['username']=user.username
        flash('Registration successful')
        return redirect(url_for('show_user', username=user.username))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session['username']=user.username
            flash('Login Successful')
            return redirect(url_for('show_user', username=user.username))
        flash('Login Unsuccessful. Please check username and password combination!')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out')
    return redirect(url_for('login'))

@app.route('/users/<username>')
def show_user(username):
    if 'username' not in session or username !=session['username']:
        flash('Please log in to view this page requested')
        return redirect(url_for('login'))
    user=User.query.filter_by(username=username).first_or_404()
    feedbacks=Feedback.query.filter_by(username=username).all()
    return render_template('user.html', user=user, feedbacks=feedbacks)

@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    if 'username' not in session or session['username'] != username:
        flash('You must be loggged in to view this page.')
        return redirect(url_for('login'))
    
    form=FeedbackForm()
    if form.validate_on_submit():
        title=form.title.data
        content=form.content.data

        new_feedback=Feedback(title=title, content=content, username=username)
        db.session.add(new_feedback)
        db.session.commit()

        flash('Feedback successfully added')
        return redirect(url_for('show_user', username=username))
    return render_template('feedback_form.html', form=form, title="Add Feedback", button_label="submit")

@app.route('/feedback/<int:feedback_id>/update', methods=['GET', 'POST'])
def update_feedback(feedback_id):
    feedback=Feedback.query.get_or_404(feedback_id)
    if 'username' not in session or session['username'] != feedback.username:
        flash('You do not have permission!')
        return redirect(url_for('login'))
    
    form=FeedbackForm(obj=feedback)
    if form.validate_on_submit():
        feedback.title=form.title.data
        feedback.content=form.content.data
        db.session.commit()
        flash('Feedback updated successfully!')
        return redirect(url_for('show_user', username=feedback.username))
    
    return render_template('feedback_form.html', form=form, title='Update Feedback', button_label='Update')

@app.route('/feedback/<int:feedback_id>/delete', methods=['POST'])
def delete_feedback(feedback_id):
    feedback=Feedback.query.get_or_404(feedback_id)
    if 'username' not in session or session['username'] != feedback.username:
        flash('You do not have permission')
        return redirect(url_for('login'))
    
    db.session.delete(feedback)
    db.session.commit()
    flash('Feedback successfully deleted!')
    return redirect(url_for('show_user', username=feedback.username))

