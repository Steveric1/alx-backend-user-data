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
    
    
def find_user_by(self, **kwargs):
        """
        Method to find user by input arguments
        Args:
           - kwargs: keyword argument
        Return:
           The first row found in the users table as filtered
        Raises:
           NoResultFound: If no rows match the query
           InvalidRequestError: If there's an issue with the query
        """
        try:
            session = self._session
            user = session.query(User).filter_by(**kwargs).first()
            if user is None:
                raise NoResultFound
            return user
        except InvalidRequestError:
            raise
