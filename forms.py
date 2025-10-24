from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired
from wtforms.validators import DataRequired, Length

class NoteForm(FlaskForm):
    title = StringField('Заголовок', validators=[DataRequired(), Length(max=100)])
    content = TextAreaField('Содержание', validators=[DataRequired()])
    submit = SubmitField('Сохранить')
