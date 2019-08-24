#!/usr/bin/env python3

"""Gruyere - a web application with holes.

Copyright 2017 Google Inc. All rights reserved.

This code is licensed under the
https://creativecommons.org/licenses/by-nd/3.0/us/
Creative Commons Attribution-No Derivative Works 3.0 United States license.

DO NOT COPY THIS CODE!

This application is a small self-contained web application with numerous
security holes. It is provided for use with the Web Application Exploits and
Defenses codelab. You may modify the code for your own use while doing the
codelab but you may not distribute the modified code. Brief excerpts of this
code may be used for educational or instructional purposes provided this
notice is kept intact. By using Gruyere you agree to the Terms of Service
https://www.google.com/intl/en/policies/terms/
"""
from __future__ import print_function

from future import standard_library
standard_library.install_aliases()
from builtins import str
__author__ = 'Bruce Leban'

# system modules
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
import cgi
import pickle
import os
import random
import sys
import threading
import socket
import urllib.request, urllib.parse, urllib.error
from urllib.parse import urlparse
from socketserver import ThreadingMixIn

try:
  sys.dont_write_bytecode = True
except AttributeError:
  pass

import gruyere_database
import gtl


DB_FILE = 'pythonsqlite.db'
SECRET_FILE = '/secret.txt'

INSTALL_PATH = '.'
RESOURCE_PATH = 'resources'

SPECIAL_COOKIE = '_cookie'
SPECIAL_PROFILE = '_profile'
SPECIAL_DB = '_db'
SPECIAL_PARAMS = '_params'
SPECIAL_UNIQUE_ID = '_unique_id'

COOKIE_UID = 'uid'
COOKIE_ADMIN = 'is_admin'
COOKIE_AUTHOR = 'is_author'


# Set to True to cause the server to exit after processing the current url.
quit_server = False

# A global copy of the database so that _GetDatabase can access it.
stored_data = None #gruyere_database.main()

# The HTTPServer object.
http_server = None

# A secret value used to generate hashes to protect cookies from tampering.
cookie_secret = ''

# File extensions of resource files that we recognize.
RESOURCE_CONTENT_TYPES = {
    '.css': 'text/css',
    '.gif': 'image/gif',
    '.htm': 'text/html',
    '.html': 'text/html',
    '.js': 'application/javascript',
    '.jpeg': 'image/jpeg',
    '.jpg': 'image/jpeg',
    '.png': 'image/png',
    '.ico': 'image/x-icon',
    '.text': 'text/plain',
    '.txt': 'text/plain',
}

allowed_ips = []

def main():
  _SetWorkingDirectory()

  global quit_server
  quit_server = False

  quit_timer = threading.Timer(7200, lambda: _Exit('Timeout'))   
  quit_timer.start()
  
  server_name = '0.0.0.0'  
  server_port = 8008                                                              

  global server_unique_id                                        
  server_unique_id = input('Enter your CTF team name: ')

  global allowed_ips
  hostname = socket.gethostname()
  ipAddr = str(socket.gethostbyname(hostname))
  
  print('-'*20 + 'Allowed IP Address List')
  print('In order for other devices to connect to your server, you must allow them by IP address')
  print('Please choose an option from the list below:')
  print('1. Allow all LAN devices (' + ipAddr[:ipAddr.rfind('.')] + '.x)')
  print('2. Specify a list of devices\n')
  
  while True:
    choice = input('Choice: ')
    try:
      if choice == '1':
        allowed_ips = [ipAddr + '.' + str(i) for i in range(0,256)]
        break
      elif choice == '2':
        ip_list = input('Please enter a comma seperated list of IP addresses:\n')
        allowed_ips = [i.strip() for i in ip_list.split(',')]
        break
      else:
        raise ValueError
    except ValueError:
      print('Sorry that was not an option please try again.')
  
  allowed_ips.append('127.0.0.1')

  global http_server
  http_server = ThreadedHTTPServer((server_name, server_port), 
                                   GruyereRequestHandler)

  print('''
      Gruyere started...
          http://%s:%d/
          http://%s:%d/%s/''' % (
              'localhost', server_port, 'localhost', server_port,
              server_unique_id), file=sys.stderr)

  global stored_data
  stored_data = _LoadDatabase()
  
  while not quit_server:
    try:
      http_server.serve_forever()
      _SaveDatabase(stored_data)
    except KeyboardInterrupt:
      print('\nReceived KeyboardInterrupt', file=sys.stderr)
      quit_server = True

  print('\nClosing', file=sys.stderr)
  http_server.socket.close()
  _Exit('quit_server')


def _Exit(reason):
  # use os._exit instead of sys.exit because this can't be trapped
  print('\nExit: ' + reason, file=sys.stderr)
  os._exit(0)


def _SetWorkingDirectory():
  """Set the working directory to the directory containing this file."""
  if sys.path[0]:
    os.chdir(sys.path[0])


def _LoadDatabase():
  """Load the database with default data if no data exists

  Returns:
    The loaded database.
  """
  global stored_data, DB_FILE
  with gruyere_database.create_connection(DB_FILE) as conn:
    sql = ''' SELECT count(*) FROM members '''
    cur = conn.cursor()
    cur.execute(sql)
    count = cur.fetchall()
    
    if count[0][0] == 0:
      members = []
      snippets = []
      print('\nLoading default data...')
      members.append(('administrator', 'admin', 'secret', 0, 1, 'My password is secret. Get it?', '', 'https://www.google.com/contact/', ''))
      members.append(('cheddar', 'Cheddar Mac', 'orange', 1, 0, 'My SSN is <a href="https://www.google.com/' +
                            'search?q=078-05-1120">078-05-1120</a>.', '', 'https://images.google.com/?q=cheddar+cheese', 'blue'))
      snippets.append(('Gruyere is the cheesiest application on the web.', 'cheddar'))
      snippets.append(('I wonder if there are any security holes in this....', 'cheddar'))
      members.append(('sardo', 'Miss Sardo', 'odras', 1, 0, 'I hate my brother Romano.', '', 'https://www.google.com/search?q="pecorino+sardo"', 'red'))
      members.append(('brie', 'Brie', 'brie', 1, 0, 'I use the same password for all my accounts.', '', 'https://news.google.com/news/search?q=brie', 'red; text-decoration:underline'))
      snippets.append(('Brie is the queen of the cheeses<span style=color:red>!!!</span>','brie'))

      for member in members:
        sql = ''' INSERT INTO members(uid, name, pw, is_author, is_admin, private_snippet, icon, web_site, color)
              VALUES(?,?,?,?,?,?,?,?,?) '''
        cur.execute(sql, member)
        
      for snippet in snippets:
        sql = ''' INSERT INTO snippets(snippet, snippet_id)
              VALUES(?,?) '''
        cur.execute(sql, snippet)
      
      conn.commit()

    stored_data = gruyere_database.get_dictionary_form(conn)
  return stored_data

def _SaveDatabase(save_database):
  """Save the database to stored-data.txt.

  Args:
    save_database: the database to save.
  """
  # compare stored_data to databaseToDict
  # if unequal figure out how the fuck to change the value
  global stored_data, DB_FILE
  with gruyere_database.create_connection(DB_FILE) as conn:
    db_data = gruyere_database.get_dictionary_form(conn)

  if stored_data != db_data:
    cur = conn.cursor()
    for member in stored_data:
      try: # Editing a prexisting member
        stored_set = set(stored_data[member].items())
        db_set = set(db_data[member].items())
        diff = dict(stored_set - db_set)
        for column in diff:
          key = column[0]
          val = column[1]
          if key == 'snippets':
            cur.execute('''DELETE FROM snippets WHERE snippet_id = ?''', (member,))
            for snip in dict(stored_set)[key]:
              sql = '''INSERT INTO snippets(snippet, snippet_id) VALUES(?,?)'''
              cur.execute(sql, (snip, member))
          else:
            sql = '''UPDATE members SET ''' + key + ''' = ? WHERE uid = ?'''
            cur.execute(sql, (column, member))    
      except KeyError: # Adding a new member and their snippets
        sql_member = '''INSERT INTO members(uid, name, pw, is_author, is_admin, private_snippet, icon, web_site, color)
              VALUES(?,?,?,?,?,?,?,?,?)'''
        sql_snippets = '''INSERT INTO snippets(snippet, snippet_id)
              VALUES(?,?)'''
        sqlmem = []
        for key,val in stored_data[member].items():
          if key == 'snippets':
            for snip in stored_data[member][key]:
              cur.execute(sql_snippets, (snip, member))
          else:
            sqlmem.append(val)
        cur.execute(sql_member, tuple(sqlmem))

    cur.commit()

class GruyereRequestHandler(BaseHTTPRequestHandler):
  """Handle a http request."""

  # An empty cookie
  NULL_COOKIE = {COOKIE_UID: None, COOKIE_ADMIN: False, COOKIE_AUTHOR: False}

  # Urls that can only be accessed by administrators.
  _PROTECTED_URLS = [
      '/quit',
      '/reset'
  ]

  
  def _GetDatabase(self):
    # Updates the stored_data dictionary
    global stored_data, DB_FILE
    conn = gruyere_database.create_connection(DB_FILE)
    stored_data = gruyere_database.get_dictionary_form(conn)
    return stored_data
 

  def _ResetDatabase(self):
    """Reset the database, deleting all members and snippets"""  
    global stored_data, DB_FILE
    conn = gruyere_database.create_connection(DB_FILE)
    cur = conn.cursor()
    cur.execute('''DELETE FROM members''')
    cur.execute('''DELETE FROM snippets''')
    conn.commit()
    stored_data = _LoadDatabase()


  def _DoLogin(self, cookie, specials, params):
    """Handles the /login url: validates the user and creates a cookie.

    Args:
      cookie: The cookie for this request.
      specials: Other special values for this request.
      params: Cgi parameters.
    """
    database = self._GetDatabase()
    message = ''
    if 'uid' in params and 'pw' in params:
      uid = self._GetParameter(params, 'uid')
      if uid in database:
          if database[uid]['pw'] == self._GetParameter(params, 'pw'):
            (cookie, new_cookie_text) = (self._CreateCookie('GRUYERE', uid))
          self._DoHome(cookie, specials, params, new_cookie_text)
          return
      message = 'Invalid user name or password.'
    # not logged in
    specials['_message'] = message
    self._SendTemplateResponse('/login.gtl', specials, params)


  def _DoLogout(self, cookie, specials, params):
    """Handles the /logout url: clears the cookie.

    Args:
      cookie: The cookie for this request.
      specials: Other special values for this request.
      params: Cgi parameters.
    """
    (cookie, new_cookie_text) = (
        self._CreateCookie('GRUYERE', None))
    self._DoHome(cookie, specials, params, new_cookie_text)


  def _Do(self, cookie, specials, params):
    """Handles the home page (http://localhost/).

    Args:
      cookie: The cookie for this request.
      specials: Other special values for this request.
      params: Cgi parameters.
    """
    self._DoHome(cookie, specials, params)


  def _DoHome(self, cookie, specials, params, new_cookie_text=None):
    """Renders the home page.

    Args:
      cookie: The cookie for this request.
      specials: Other special values for this request.
      params: Cgi parameters.
      new_cookie_text: New cookie.
    """
    database = self._GetDatabase()
    specials[SPECIAL_COOKIE] = cookie
    if cookie and cookie.get(COOKIE_UID):
      specials[SPECIAL_PROFILE] = database.get(cookie[COOKIE_UID])
    else:
      specials.pop(SPECIAL_PROFILE, None)
    self._SendTemplateResponse(
        '/home.gtl', specials, params, new_cookie_text)


  def _DoBadUrl(self, path, cookie, specials, params):
    """Handles invalid urls: displays an appropriate error message.

    Args:
      path: The invalid url.
      cookie: The cookie for this request.
      specials: Other special values for this request.
      params: Cgi parameters.
    """
    self._SendError('Invalid request: %s' % (path,), cookie, specials, params)


  def _DoQuitserver(self, cookie, specials, params):
    """Handles the /quitserver url for administrators to quit the server.

    Args:
      cookie: The cookie for this request. (unused)
      specials: Other special values for this request. (unused)
      params: Cgi parameters. (unused)
    """
    global quit_server
    quit_server = True
    self._SendTextResponse('Server quit.', None)


  def _AddParameter(self, name, params, data_dict, default=None):
    """Transfers a value (with a default) from the parameters to the data."""
    if params.get(name):
      data_dict[name] = params[name][0]
    elif default is not None:
      data_dict[name] = default


  def _GetParameter(self, params, name, default=None):
    """Gets a parameter value with a default."""
    if params.get(name):
      return params[name][0]
    return default


  def _GetSnippets(self, cookie, specials, create=False):
    """Returns all of the user's snippets."""
    database = self._GetDatabase()
    try:
      profile = database[cookie[COOKIE_UID]]
      if create and 'snippets' not in profile:
        profile['snippets'] = []
      snippets = profile['snippets']
    except (KeyError, TypeError):
      _Log('Error getting snippets')
      return None
    print(snippets)
    return snippets


  def _DoNewsnippet2(self, cookie, specials, params):
    """Handles the /newsnippet2 url: actually add the snippet.

    Args:
      cookie: The cookie for this request.
      specials: Other special values for this request.
      params: Cgi parameters.
    """
    snippet = self._GetParameter(params, 'snippet')
    if not snippet:
      self._SendError('No snippet!', cookie, specials, params)
    else:
      snippets = self._GetSnippets(cookie, specials, True)
      if snippets is not None:
        #snippets.insert(0, snippet)
        # need to make sure the snippet variablw is indeed a
        # sting of text, looks like it is but double check
        gruyere_database.create_snippet(stored_data, snippet)
    self._SendRedirect('/snippets.gtl', specials[SPECIAL_UNIQUE_ID])


  def _DoDeletesnippet(self, cookie, specials, params):
    """Handles the /deletesnippet url: delete the indexed snippet.

    Args:
      cookie: The cookie for this request.
      specials: Other special values for this request.
      params: Cgi parameters.
    """
    # index may be the row id 
    index = self._GetParameter(params, 'index')
    #snippets = self._GetSnippets(cookie, specials)
    try:
      gruyere_database.delete_snippet(stored_data, index)
      #del snippets[int(index)]
    except (IndexError, TypeError, ValueError):
      self._SendError(
          'Invalid index (%s)' % (index,),
          cookie, specials, params)
      return
    self._SendRedirect('/snippets.gtl', specials[SPECIAL_UNIQUE_ID])


  def _DoSaveprofile(self, cookie, specials, params):
    """Saves the user's profile.

    Args:
      cookie: The cookie for this request.
      specials: Other special values for this request.
      params: Cgi parameters.

    If the 'action' cgi parameter is 'new', then this is creating a new user
    and it's an error if the user already exists. If action is 'update', then
    this is editing an existing user's profile and it's an error if the user
    does not exist.
    """
    
    # build new profile
    profile_data = {}
    uid = self._GetParameter(params, 'uid', cookie[COOKIE_UID])
    newpw = self._GetParameter(params, 'pw')
    self._AddParameter('uid', params, profile_data)
    self._AddParameter('name', params, profile_data)
    self._AddParameter('pw', params, profile_data)
    self._AddParameter('is_author', params, profile_data)
    self._AddParameter('is_admin', params, profile_data)
    self._AddParameter('private_snippet', params, profile_data)
    self._AddParameter('icon', params, profile_data)
    self._AddParameter('web_site', params, profile_data)
    self._AddParameter('color', params, profile_data)

    with gruyere_database.create_connection(DB_FILE) as conn:
      cur = conn.cursor()
      # Each case below has to set either error or redirect
      message = None
      new_cookie_text = None
      action = self._GetParameter(params, 'action')
      if action == 'new':
        cur.execute("SELECT * FROM members WHERE uid=?", (uid,))
        if cur.fetchall()!=[]:
          message = 'User already exists.'
        else:
          profile_data['pw'] = newpw
          # create a new profile using the profile_data variable
          # this is the reverse of get profile essentially
          cur.execute("PRAGMA table_info(members)")
          columns = cur.fetchall()
          columns = columns[1:len(columns)] # omits id column
          member = []
          # this shit adds nones need to construct user correctly
          # params = {'action': ['new'], 'uid': ['test'], 'pw': ['test'], 'is_author': ['True']}
          for column in columns:
            try:
              if params[column[1]] is not None:
                if column[2] == 'integer':
                  if params[column[1]][0] == 'True': # maybe use dictionary here instead
                    member.append(1)
                  else:
                    member.append(0)
                else:
                  member.append(params[column[1]][0]) 
            except KeyError:
              member.append("""NULL""")
          member = tuple(member)
          sql = ''' INSERT INTO members(uid, name, pw, is_author, is_admin, private_snippet, icon, web_site, color)
              VALUES(?,?,?,?,?,?,?,?,?) '''
          cur.execute(sql, member)
          conn.commit()
          (cookie, new_cookie_text) = self._CreateCookie('GRUYERE', uid)
          message = 'Account created.'  # error message can also indicates success
      elif action == 'update':
        cur.execute("SELECT * FROM members WHERE uid=?", (uid,))
        if cur.fetchall()==[]:
          message = 'User does not exist.'
        elif (newpw and ((cur.execute("SELECT pw FROM members WHERE uid=?", (uid,))).fetchall())[0][0] != self._GetParameter(params, 'oldpw')
              and not cookie.get(COOKIE_ADMIN)):
          # must be admin or supply old pw to change password
          message = 'Incorrect password.'
        else:
          if newpw:
            profile_data['pw'] = newpw
          # update a member using the profile_data
          # maybe encapsulate repetitive code into local convert profile function
          #database[uid].update(profile_data)
          columns = gruyere_database.get_member_columns(stored_data)
          member = ()
          for i,column in enumerate(columns):
            if i < len(columns):
              member += (self._GetParameter(params, column[1]),)
            else:
              member += (self._GetParameter(params, column[1]))
          gruyere_database.update_member(stored_data, member)
          redirect = '/'
      else:
        message = 'Invalid request'
      _Log('SetProfile(%s, %s): %s' %(str(uid), str(action), str(message)))
      if message:
        self._SendError(message, cookie, specials, params, new_cookie_text)
      else:
        self._SendRedirect(redirect, specials[SPECIAL_UNIQUE_ID])
      conn.commit()

  def _SendHtmlResponse(self, html, new_cookie_text=None):
    """Sends the provided html response with appropriate headers.

    Args:
      html: The response.
      new_cookie_text: New cookie to set.
    """
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.send_header('Pragma', 'no-cache')
    if new_cookie_text:
      self.send_header('Set-Cookie', new_cookie_text)
    self.send_header('X-XSS-Protection', '0')
    self.end_headers()
    self.wfile.write(html.encode())

  def _SendTextResponse(self, text, new_cookie_text=None):
    """Sends a verbatim text response."""

    self._SendHtmlResponse('<pre>' + cgi.escape(text) + '</pre>',
                           new_cookie_text)

  def _SendTemplateResponse(self, filename, specials, params,
                            new_cookie_text=None):
    """Sends a response using a gtl template.

    Args:
      filename: The template file.
      specials: Other special values for this request.
      params: Cgi parameters.
      new_cookie_text: New cookie to set.
    """
    f = None
    try:
      f = open(RESOURCE_PATH + filename, 'r')
      template = f.read()
    finally:
      if f: f.close()
    self._SendHtmlResponse(
        gtl.ExpandTemplate(template, specials, params),
        new_cookie_text)

  def _SendFileResponse(self, filename, cookie, specials, params):
    """Sends the contents of a file.

    Args:
      filename: The file to send.
      cookie: The cookie for this request.
      specials: Other special values for this request.
      params: Cgi parameters.
    """
    content_type = None
    if filename.endswith('.gtl'):
      self._SendTemplateResponse(filename, specials, params)
      return

    name_only = filename[filename.rfind('/'):]
    extension = name_only[name_only.rfind('.'):]
    if '.' not in extension:
      content_type = 'text/plain'
    elif extension in RESOURCE_CONTENT_TYPES:
      content_type = RESOURCE_CONTENT_TYPES[extension]
    else:
      self._SendError(
          'Unrecognized file type (%s).' % (filename,),
          cookie, specials, params)
      return
    f = None
    try:
      f = open(RESOURCE_PATH + filename, 'rb')
      self.send_response(200)
      self.send_header('Content-type', content_type)
      # Always cache static resources
      self.send_header('Cache-control', 'public, max-age=7200')
      self.send_header('X-XSS-Protection', '0')
      self.end_headers()
      self.wfile.write(f.read())
    finally:
      if f: f.close()

  def _SendError(self, message, cookie, specials, params, new_cookie_text=None):
    """Sends an error message (using the error.gtl template).

    Args:
      message: The error to display.
      cookie: The cookie for this request. (unused)
      specials: Other special values for this request.
      params: Cgi parameters.
      new_cookie_text: New cookie to set.
    """
    specials['_message'] = message
    self._SendTemplateResponse(
        '/error.gtl', specials, params, new_cookie_text)

  def _CreateCookie(self, cookie_name, uid):
    """Creates a cookie for this user.

    Args:
      cookie_name: Cookie to create.
      uid: The user.

    Returns:
      (cookie, new_cookie_text).

    The cookie contains all the information we need to know about
    the user for normal operations, including whether or not the user
    should have access to the authoring pages or the admin pages.
    The cookie is signed with a hash function.
    """
    if uid is None:
      return (self.NULL_COOKIE, cookie_name + '=; path=/')
    database = self._GetDatabase()
    profile = database[uid]
    if profile.get('is_author', 0):
      is_author = 'author'
    else:
      is_author = ''
    if profile.get('is_admin', 0):
      is_admin = 'admin'
    else:
      is_admin = ''

    c = {COOKIE_UID: uid, COOKIE_ADMIN: is_admin, COOKIE_AUTHOR: is_author}
    c_data = '%s|%s|%s' % (uid, is_admin, is_author)

    # global cookie_secret; only use positive hash values
    h_data = str(hash(cookie_secret + c_data) & 0x7FFFFFF)
    c_text = '%s=%s|%s; path=/' % (cookie_name, h_data, c_data)
    return (c, c_text)

  def _GetCookie(self, cookie_name):
    """Reads, verifies and parses the cookie.

    Args:
      cookie_name: The cookie to get.

    Returns:
      a dict containing user, is_admin, and is_author if the cookie
      is present and valid. Otherwise, None.
    """
    cookies = self.headers.get('Cookie')
    if isinstance(cookies, str):
      for c in cookies.split(';'):
        matched_cookie = self._MatchCookie(cookie_name, c)
        if matched_cookie:
          return self._ParseCookie(matched_cookie)
    return self.NULL_COOKIE

  def _MatchCookie(self, cookie_name, cookie):
    """Matches the cookie.

    Args:
      cookie_name: The name of the cookie.
      cookie: The full cookie (name=value).

    Returns:
      The cookie if it matches or None if it doesn't match.
    """
    try:
      (cn, cd) = cookie.strip().split('=', 1)
      if cn != cookie_name:
        return None
    except (IndexError, ValueError):
      return None
    return cd

  def _ParseCookie(self, cookie):
    """Parses the cookie and returns NULL_COOKIE if it's invalid.

    Args:
      cookie: The text of the cookie.

    Returns:
      A map containing the values in the cookie.
    """
    try:
      (hashed, cookie_data) = cookie.split('|', 1)
      # global cookie_secret
      if hashed != str(hash(cookie_secret + cookie_data) & 0x7FFFFFF):
        return self.NULL_COOKIE
      values = cookie_data.split('|')
      return {
          COOKIE_UID: values[0],
          COOKIE_ADMIN: values[1] == 'admin',
          COOKIE_AUTHOR: values[2] == 'author',
      }
    except (IndexError, ValueError):
      return self.NULL_COOKIE

  def _DoReset(self, cookie, specials, params):  # debug only; resets this db
    """Handles the /reset url for administrators to reset the database.

    Args:
      cookie: The cookie for this request. (unused)
      specials: Other special values for this request. (unused)
      params: Cgi parameters. (unused)
    """
    self._SendTextResponse('Server reset to default values...', None)

  def _DoUpload2(self, cookie, specials, params):
    """Handles the /upload2 url: finish the upload and save the file.

    Args:
      cookie: The cookie for this request.
      specials: Other special values for this request.
      params: Cgi parameters. (unused)
    """
    (filename, file_data) = self._ExtractFileFromRequest()
    directory = self._MakeUserDirectory(cookie[COOKIE_UID])

    message = None
    url = None
    try:
      f = open(directory + filename, 'wb')
      f.write(file_data)
      f.close()
      (host, port) = http_server.server_address
      url = 'http://%s:%d/%s/%s/%s' % (
          host, port, specials[SPECIAL_UNIQUE_ID], cookie[COOKIE_UID], filename)
    except IOError:
      message = 'Couldn\'t write file %s' % (filename)
      _Log(message)

    specials['_message'] = message
    self._SendTemplateResponse(
        '/upload2.gtl', specials,
        {'url': url})

  def _ExtractFileFromRequest(self):
    """Extracts the file from an upload request.

    Returns:
      (filename, file_data)
    """
    form = cgi.FieldStorage(
        fp=self.rfile,
        headers=self.headers,
        environ={'REQUEST_METHOD': 'POST',
                 'CONTENT_TYPE': self.headers.get('content-type')})          

    upload_file = form['upload_file']
    file_data = upload_file.file.read()
    return (upload_file.filename, file_data)

  # could make this managed by db
  def _MakeUserDirectory(self, uid):
    """Creates a separate directory for each user to avoid upload conflicts.

    Args:
      uid: The user to create a directory for.

    Returns:
      The new directory path (/uid/).
    """

    directory = RESOURCE_PATH + os.sep + str(uid) + os.sep
    try:
      os.mkdir(directory)
      # throws an exception if directory already exists,
      # however exception type varies by platform
    except Exception:
      pass  # just ignore it if it already exists
    return directory

  def _SendRedirect(self, url, unique_id):
    """Sends a 302 redirect.

    Automatically adds the unique_id.

    Args:
      url: The location to redirect to which must start with '/'.
      unique_id: The unique id to include in the url.
    """
    if not url:
      url = '/'
    url = '/' + unique_id + url
    self.send_response(302)
    self.send_header('Location', url)
    self.send_header('Pragma', 'no-cache')
    self.send_header('Content-type', 'text/html')
    self.send_header('X-XSS-Protection', '0')
    self.end_headers()
    res = u'''<!DOCTYPE HTML PUBLIC '-//W3C//DTD HTML//EN'>
    <html><body>
    <title>302 Redirect</title>
    Redirected <a href="%s">here</a>
    </body></html>''' % (url)
    self.wfile.write(res.encode())

  def _GetHandlerFunction(self, path):
    try:
      return getattr(GruyereRequestHandler, '_Do' + path[1:].capitalize())
    except AttributeError:
      return None

  def do_POST(self):  # part of BaseHTTPRequestHandler interface
    self.DoGetOrPost()

  def do_GET(self):  # part of BaseHTTPRequestHandler interface
    self.DoGetOrPost()

  def DoGetOrPost(self):
    global allowed_ips
    """Validate an http get or post request and call HandleRequest."""

    url = urlparse(self.path)
    path = url[2]
    query = url[4]

   #Network Security settings

    request_ip = self.client_address[0]                      
    if request_ip not in allowed_ips:                        
      print((                                  
          'DANGER! Request from bad ip: ' + request_ip), file=sys.stderr)      
      _Exit('bad_ip')                                        

    if (server_unique_id not in path                         
        and path != '/favicon.ico'):                         
      if path == '' or path == '/':                          
        self._SendRedirect('/', server_unique_id)            
        return                                               
      else:                                                  
        print((                                
            'DANGER! Request without unique id: ' + path), file=sys.stderr)    
        #_Exit('bad_id')                                      

    path = path.replace('/' + server_unique_id, '', 1)       

  

    self.HandleRequest(path, query, server_unique_id)

  def HandleRequest(self, path, query, unique_id):
    """Handles an http request.

    Args:
      path: The path part of the url, with leading slash.
      query: The query part of the url, without leading question mark.
      unique_id: The unique id from the url.
    """
    global stored_data
    path = urllib.parse.unquote(path)
    stored_data = self._GetDatabase()
    if not path:
      self._SendRedirect('/', server_unique_id)
      return
    params = urllib.parse.parse_qs(query)  # url.query
    specials = {}
    cookie = self._GetCookie('GRUYERE')
    specials[SPECIAL_COOKIE] = cookie
    specials[SPECIAL_DB] = stored_data
    specials[SPECIAL_PROFILE] = stored_data.get(cookie.get(COOKIE_UID))
    specials[SPECIAL_PARAMS] = params
    specials[SPECIAL_UNIQUE_ID] = unique_id

    if path in self._PROTECTED_URLS and not cookie[COOKIE_ADMIN]:
      self._SendError('Invalid request', cookie, specials, params)
      return

    try:
      handler = self._GetHandlerFunction(path)
      if callable(handler):
        (handler)(self, cookie, specials, params)
      else:
        try:
          self._SendFileResponse(path, cookie, specials, params)
        except IOError:
          self._DoBadUrl(path, cookie, specials, params)
    except KeyboardInterrupt:
      _Exit('KeyboardInterrupt')

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
  """Handle requests in a separate thread."""

def _Log(message):
  print(message, file=sys.stderr)


if __name__ == '__main__':
  main()
