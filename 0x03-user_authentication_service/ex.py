#!/usr/bin/python3

from flask import Flask

app = Flask(__name__)

print(app)


@app.route('/')
def hello_world():
    return 'Hello, World!'


@app.route('/projects/')
def projects():
    return 'The project page'


@app.route('/about')
def about():
    return 'The about page'


if __name__ == '__main__':
    app.run()
