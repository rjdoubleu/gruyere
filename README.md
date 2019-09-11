# GruyereOnSQL: Google Gruyere with a Twist

## Warning
Do not distribute this code outside of a classroom environment. Any modifications made to this code are simply an attempt of enhancing the prexisting curriculum and to continue the platform's ease of use and deployment. Please follow this curriculum found at (Google-Gruyere)[https://google-gruyere.appspot.com/]. Once the SQL backend is complete, an addition SQL injection curriculum will be included in this repository.

## The Goal
Create a version of Gruyere perfect for a small CTF. The to do list is as follows:

- (Completed) CLI suuport for CTF environment
- (Completed) HTTP Threading for multiple connections 
- (Backlogged) Create SQL backend to replace the current dictionary database
- (Backlogged) Encrypt password storage using SHA-256 

## Whats's New?
In this version I added HTTP threading as to reliably allow multiple connections to the webpage. 
In addition I added a friendly CLI for specifying a Team Name and allowed IP adress list automation.

## Setup Note 
In order to connect to a remote server, the server must be referenced by it's ip address and broadcasting port using the follwoing syntax: http://255.255.255.255:8008 . Additionally **you should not run this exposed to an active internet connection while accepting all ip addresses**. Doing so will serioulsy endanger the host machine the server is running on. Instead the best practice is to use a router devouted only to the CTF. Anyone who wants to connect to the web server must therefore be connected to the same router. **The router may have internet access enabled only if the server is only accepting local connections**. Otherwise it is simply not worth the risk.

## Usage 

Clone or download this and run ./gruyere.py or python gruyere.py and the follow the instructions in the CLI

You might need to `pip install future` if the host machine does not already have the library installed.

Tested on Linux/Unix/Windows with Python 2.7, 3.6 and 3.7

## Credits
Base code is Copyright 2017 Google Inc. All Rights Reserved.

This code is licensed under the http://creativecommons.org/licenses/by-nd/3.0/us
Creative Commons Attribution-No Derivative Works 3.0 United States license.
