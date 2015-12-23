Project 3: Catalog Application
==============================

## Prerequisites

This application requires Python 3 with Flask and SQLAlchemy. This application implements authentication with Google+'s OAuth2 API so you will also need a Google account to set up your own client secrets.

## Setup

First run database_setup.py, this will create the SQLite database that the flask application runs on.
 
To set up the client secrets file:
 
1. Navigate to https://console.developers.google.com and log in with your Google account.
2. Create a new project and enable the Google+ API.
3. With the Google+ API selected a tab called 'Credentials' should appear, click that tab.
4. In the credentials tab click 'New Credentials' and select OAuth Client ID. 
5. This new set of credentials should have an authorized Javascript origin and Authorized redirect URI that point to http://yoururl.here:8000.
6. Once this is complete you can click the 'download json' button to download the required json file. It should be saved as *client_secret.json* in the same directory as application.py and database_setup.py.
 
Before running this in production you should generate a new Flask secret key to a random string. This can be found at the end of application.py at the line that starts with app.secret_key =, without doing this anyone who has seen this repository can decrypt your client sessions and modify your session data which is a security risk.

To run the actual application run application.py. This will listen on port 8000 across all interfaces.


## API Endpoints

The application provides the following endpoints for programmatic acccess.

* `/recent-categories.atom` - An Atom feed that lists the latest categories by creation date.
* `/recent-items.atom` - An Atom feed that lists the latest items by creation date.
* `/category/<category_name>/json` - Lists all items in a category in JSON format.
* `/categories/json` - Lists all categories in JSON format.

## General Routes

* `/` - Index page which lists the 10 largest categories and 10 of the latest items.
* `/login` - A login page which contains the Google+ login button.
* `/logout` - A logout page.
* `/category/new` - Form to create a new category, requires logging in.
* `/category/<category>` - Page to view all items in a category.
* `/item/<category>/<item_name>/view` - Page to view a particular item.
* `/item/<category>/<item_name>/edit` - Page to edit a particular item.
* `/item/<category>/<item_name>/delete` - Page to delete a particular item.

