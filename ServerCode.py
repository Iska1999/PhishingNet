from flask import Flask, jsonify, request
from keras.models import load_model
import ssl, socket
import requests
from datetime import datetime
import tldextract
import ipaddress as ip
from urllib.parse import urlparse
from urllib.request import urlopen
import os
import os.path
from os import path
cwd = os.getcwd()
import sys
sys.path.append(cwd)
import Model
import time
import numpy as np
import pandas as pd
app = Flask(__name__)
global current_url 

if (path.exists('PhishingNet.h5')):
    model = load_model('PhishingNet.h5')
    print("Loaded model from disk")
else:        
    model=Model.train_model()
    print("Saved model to disk")

def featureExtraction(url_input):
  test_url = str(url_input)
  parsed_test_url = urlparse(test_url)
  features = []
  
  #define netloc
  netloc_part = parsed_test_url.netloc #subdomain + domain + suffix
  netloc_string = str(netloc_part)
  print(netloc_string)
  #define domain
  extraction = tldextract.extract(url_input) 
  domain_part = extraction.domain
  domain_string = str(domain_part)
  print(domain_string)
  #define suffix
  suffix_part = extraction.suffix
  suffix_string = str(suffix_part)
  #define directory 
  path_part = parsed_test_url.path
  path_string = str(path_part)
  def strip_scheme(url):
    parsed = urlparse(url)
    scheme = "%s://" % parsed.scheme
    return parsed.geturl().replace(scheme, '', 1)

#here, we are testing different features of the url
  try:
    #1- quantity . in url
    qty_dot_url = test_url.count('.')
    features.append(qty_dot_url)
    #2- quantity - in url
    qty_hyphen_url = test_url.count('-')
    features.append(qty_hyphen_url)
    #3- quantity _ in url
    qty_underline_url = test_url.count('_')
    features.append(qty_underline_url)
    #4- quantity / in url
    qty_slash_url = test_url.count('/')
    features.append(qty_slash_url)
    #5- quantity ? in url
    qty_questionmark_url = test_url.count('?')
    features.append(qty_questionmark_url)
    #6- quantity = in url
    qty_equal_url = test_url.count('=')
    features.append(qty_equal_url)
    #7- quantity @ in url
    qty_at_url = test_url.count('@')
    features.append(qty_at_url)
    #8- quantity & in url
    qty_and_url = test_url.count('&')
    features.append(qty_and_url)
    #9- quantity ! in url
    qty_exclamation_url = test_url.count('!')
    features.append(qty_exclamation_url)
    #10- quantity space in url
    qty_space_url = test_url.count(' ')
    features.append(qty_space_url)
    #11- quantity ~ in url
    qty_tilde_url = test_url.count('~')
    features.append(qty_tilde_url)
    #12- quantity , in url
    qty_comma_url = test_url.count(',')
    features.append(qty_comma_url)
    #13- quantity + in url
    qty_plus_url = test_url.count('+')
    features.append(qty_plus_url)
    #14- quantity * in url
    qty_asterisk_url = test_url.count('*')
    features.append(qty_asterisk_url)
    #15- quantity # in url
    qty_hashtag_url = test_url.count('#')
    features.append(qty_hashtag_url)
    #16- quantity $ in url
    qty_dollar_url = test_url.count('$')
    features.append(qty_dollar_url)
    #17- quantity % in url
    qty_percent_url = test_url.count('%')
    features.append(qty_percent_url)
    #18- number of shady top-level domains in url
    shadyTopLevelDomainsList = ['work', 'men', 'click','gdn','loan','top','cf','gq','ml','ga','monster','accountants','life','desi','buzz','country','ooo','stream','download','xin','nagoya', 'racing','win', 'ryukyu']
    qty_tld_url = 0
    if suffix_string in shadyTopLevelDomainsList:
      qty_tld_url = qty_tld_url + 1
    features.append(qty_tld_url)
    #19-check url length
    url_length = len(test_url)
    features.append(url_length)
  except:
    qty_dot_url = 0
    features.append(qty_dot_url)
    qty_hyphen_url = 0
    features.append(qty_hyphen_url)
    qty_underline_url = 0
    features.append(qty_underline_url)
    qty_slash_url = 0
    features.append(qty_slash_url)
    qty_questionmark_url = 0
    features.append(qty_questionmark_url)
    qty_equal_url = 0
    features.append(qty_equal_url)
    qty_at_url = 0
    features.append(qty_at_url)
    qty_and_url = 0
    features.append(qty_and_url)
    qty_exclamation_url = 0
    features.append(qty_exclamation_url)
    qty_space_url = 0
    features.append(qty_space_url)
    qty_tilde_url = 0
    features.append(qty_tilde_url)
    qty_comma_url = 0
    features.append(qty_comma_url)
    qty_plus_url = 0
    features.append(qty_plus_url)
    qty_asterisk_url = 0
    features.append(qty_asterisk_url)
    qty_hashtag_url = 0
    features.append(qty_hashtag_url)
    qty_dollar_url = 0
    features.append(qty_dollar_url)
    qty_percent_url = 0
    features.append(qty_percent_url)
    qty_tld_url = 0
    features.append(qty_tld_url)
    url_length = 0
    features.append(url_length)

#here, we are testing different features of the domain
  try:
    #20- quantity . in domain
    qty_dot_domain = domain_string.count('.')
    features.append(qty_dot_domain)
    #21- quantity - in domain
    qty_hyphen_domain = domain_string.count('-')
    features.append(qty_hyphen_domain)
    #22- quantity _ in domain
    qty_underline_domain = domain_string.count('_')
    features.append(qty_underline_domain)
    #23- quantity / in domain
    qty_slash_domain = domain_string.count('/')
    features.append(qty_slash_domain)
    #24- quantity ? in domain
    qty_questionmark_domain = domain_string.count('?')
    features.append(qty_questionmark_domain)
    #25- quantity = in domain
    qty_equal_domain = domain_string.count('=')
    features.append(qty_equal_domain)
    #26- quantity @ in domain
    qty_at_domain = domain_string.count('@')
    features.append(qty_at_domain)
    #27- quantity & in domain
    qty_and_domain = domain_string.count('&')
    features.append(qty_and_domain)
    #28- quantity ! in domain
    qty_exclamation_domain = domain_string.count('!')
    features.append(qty_exclamation_domain)
    #29- quantity space in domain
    qty_space_domain = domain_string.count(' ')
    features.append(qty_space_domain)
    #30- quantity ~ in domain
    qty_tilde_domain = domain_string.count('~')
    features.append(qty_tilde_domain)
    #31- quantity , in domain
    qty_comma_domain = domain_string.count(',')
    features.append(qty_comma_domain)
    #32- quantity + in domain
    qty_plus_domain = domain_string.count('+')
    features.append(qty_plus_domain)
    #33- quantity * in domain
    qty_asterisk_domain = domain_string.count('*')
    features.append(qty_asterisk_domain)
    #34- quantity # in domain
    qty_hashtag_domain = domain_string.count('#')
    features.append(qty_hashtag_domain)
    #35- quantity $ in domain
    qty_dollar_domain = domain_string.count('$')
    features.append(qty_dollar_domain)
    #36- quantity % in domain
    qty_percent_domain = domain_string.count('%')
    features.append(qty_percent_domain)
    #37- number of vowels in domain
    vowelsList = ['a', 'e', 'i','o','u']
    qty_vowels_domain = 0
    for character in domain_string:
      if character in vowelsList:
        qty_vowels_domain = qty_vowels_domain + 1
    features.append(qty_vowels_domain)
    #38-check domain length
    domain_length = len(domain_string)
    features.append(domain_length)
  except:
    qty_dot_domain = 0
    features.append(qty_dot_domain)
    qty_hyphen_domain = 0
    features.append(qty_hyphen_domain)
    qty_underline_domain = 0
    features.append(qty_underline_domain)
    qty_slash_domain = 0
    features.append(qty_slash_domain)
    qty_questionmark_domain = 0
    features.append(qty_questionmark_domain)
    qty_equal_domain = 0
    features.append(qty_equal_domain)
    qty_at_domain = 0
    features.append(qty_at_domain)
    qty_and_domain = 0
    features.append(qty_and_domain)
    qty_exclamation_domain = 0
    features.append(qty_exclamation_domain)
    qty_space_domain = 0
    features.append(qty_space_domain)
    qty_tilde_domain = 0
    features.append(qty_tilde_domain)
    qty_comma_domain = 0
    features.append(qty_comma_domain)
    qty_plus_domain = 0
    features.append(qty_plus_domain)
    qty_asterisk_domain = 0
    features.append(qty_asterisk_domain)
    qty_hashtag_domain = 0
    features.append(qty_hashtag_domain)
    qty_dollar_domain = 0
    features.append(qty_dollar_domain)
    qty_percent_domain = 0
    features.append(qty_percent_domain)
    qty_vowels_domain = 0
    features.append(qty_vowels_domain)
    domain_length = 0
    features.append(domain_length)

#here, we are testing different features of the directory (path)
  try:
    if path_string != "":
      #39- quantity . in directory
      qty_dot_directory = path_string.count('.')
      #40- quantity - in directory
      qty_hyphen_directory = path_string.count('-')
      #41- quantity _ in directory
      qty_underline_directory = path_string.count('_')
      #42- quantity / in directory
      qty_slash_directory = path_string.count('/')
      #43- quantity ? in directory
      qty_questionmark_directory = path_string.count('?')
      #44- quantity = in directory
      qty_equal_directory = path_string.count('=')
      #45- quantity @ in directory
      qty_at_directory = path_string.count('@')
      #46- quantity & in directory
      qty_and_directory = path_string.count('&')
      #47- quantity ! in directory
      qty_exclamation_directory = path_string.count('!')
      #48- quantity space in directory
      qty_space_directory = path_string.count(' ')
      #49- quantity ~ in directory
      qty_tilde_directory = path_string.count('~')
      #50- quantity , in directory
      qty_comma_directory = path_string.count(',')
      #51- quantity + in directory
      qty_plus_directory = path_string.count('+')
      #52- quantity * in directory
      qty_asterisk_directory = path_string.count('*')
      #53- quantity # in directory
      qty_hashtag_directory = path_string.count('#')
      #54- quantity $ in directory
      qty_dollar_directory = path_string.count('$')
      #55- quantity % in directory
      qty_percent_directory = path_string.count('%')
      #56-check directory length
      directory_length = len(path_string)
    else:
      qty_dot_directory = 0
      qty_hyphen_directory = 0
      qty_underline_directory = 0
      qty_slash_directory = 0
      qty_questionmark_directory = 0
      qty_equal_directory = 0
      qty_at_directory = 0
      qty_and_directory = 0
      qty_exclamation_directory = 0
      qty_space_directory = 0
      qty_tilde_directory = 0
      qty_comma_directory = 0
      qty_plus_directory = 0
      qty_asterisk_directory = 0
      qty_hashtag_directory = 0
      qty_dollar_directory = 0
      qty_percent_directory = 0
      directory_length = 0
  except:
    qty_dot_directory = 0
    qty_hyphen_directory = 0
    qty_underline_directory = 0
    qty_slash_directory = 0
    qty_questionmark_directory = 0
    qty_equal_directory = 0
    qty_at_directory = 0
    qty_and_directory = 0
    qty_exclamation_directory = 0
    qty_space_directory = 0
    qty_tilde_directory = 0
    qty_comma_directory = 0
    qty_plus_directory = 0
    qty_asterisk_directory = 0
    qty_hashtag_directory = 0
    qty_dollar_directory = 0
    qty_percent_directory = 0
    directory_length = 0
  features.append(qty_dot_directory)
  features.append(qty_hyphen_directory)
  features.append(qty_underline_directory)
  features.append(qty_slash_directory)
  features.append(qty_questionmark_directory)
  features.append(qty_equal_directory)
  features.append(qty_at_directory)
  features.append(qty_and_directory)
  features.append(qty_exclamation_directory)
  features.append(qty_space_directory)
  features.append(qty_tilde_directory)
  features.append(qty_comma_directory)
  features.append(qty_plus_directory)
  features.append(qty_asterisk_directory)
  features.append(qty_hashtag_directory)
  features.append(qty_dollar_directory)
  features.append(qty_percent_directory)
  features.append(directory_length)

#here, we are testing different features of the parameters
  try:
    parameters_part = parsed_test_url.parameters
    params_string = str(parameters_part)
    if params_string != "":
      #57- quantity . in params
      qty_dot_params = params_string.count('.')
      #58- quantity - in params
      qty_hyphen_params = params_string.count('-')
      #59- quantity _ in params
      qty_underline_params = params_string.count('_')
      #60- quantity / in params
      qty_slash_params = params_string.count('/')
      #61- quantity ? in params
      qty_questionmark_params = params_string.count('?')
      #62- quantity = in params
      qty_equal_params = params_string.count('=')
      #63- quantity @ in params
      qty_at_params = params_string.count('@')
      #64- quantity & in params
      qty_and_params = params_string.count('&')
      #65- quantity ! in params
      qty_exclamation_params = params_string.count('!')
      #66- quantity space in params
      qty_space_params = params_string.count(' ')
      #67- quantity ~ in params
      qty_tilde_params = params_string.count('~')
      #68- quantity , in params
      qty_comma_params = params_string.count(',')
      #69- quantity + in params
      qty_plus_params = params_string.count('+')
      #70- quantity * in params
      qty_asterisk_params = params_string.count('*')
      #71- quantity # in params
      qty_hashtag_params = params_string.count('#')
      #72- quantity $ in params
      qty_dollar_params = params_string.count('$')
      #73- quantity % in params
      qty_percent_params = params_string.count('%')
      #74-check params length
      params_length = len(params_string)
    else:
      qty_dot_params = 0
      qty_hyphen_params = 0
      qty_underline_params = 0
      qty_slash_params = 0
      qty_questionmark_params = 0
      qty_equal_params = 0
      qty_at_params = 0
      qty_and_params = 0
      qty_exclamation_params = 0
      qty_space_params = 0
      qty_tilde_params = 0
      qty_comma_params = 0
      qty_plus_params = 0
      qty_asterisk_params = 0
      qty_hashtag_params = 0
      qty_dollar_params = 0
      qty_percent_params = 0
      params_length = 0
    features.append(qty_dot_directory)
    features.append(qty_hyphen_directory)
    features.append(qty_underline_directory)
    features.append(qty_slash_directory)
    features.append(qty_questionmark_directory)
    features.append(qty_equal_directory)
    features.append(qty_at_directory)
    features.append(qty_and_directory)
    features.append(qty_exclamation_directory)
    features.append(qty_space_directory)
    features.append(qty_tilde_directory)
    features.append(qty_comma_directory)
    features.append(qty_plus_directory)
    features.append(qty_asterisk_directory)
    features.append(qty_hashtag_directory)
    features.append(qty_dollar_directory)
    features.append(qty_percent_directory)
    features.append(directory_length)
  except:
    qty_dot_params = 0
    qty_hyphen_params = 0
    qty_underline_params = 0
    qty_slash_params = 0
    qty_questionmark_params = 0
    qty_equal_params = 0
    qty_at_params = 0
    qty_and_params = 0
    qty_exclamation_params = 0
    qty_space_params = 0
    qty_tilde_params = 0
    qty_comma_params = 0
    qty_plus_params = 0
    qty_asterisk_params = 0
    qty_hashtag_params = 0
    qty_dollar_params = 0
    qty_percent_params = 0
    params_length = 0
    features.append(qty_dot_directory)
    features.append(qty_hyphen_directory)
    features.append(qty_underline_directory)
    features.append(qty_slash_directory)
    features.append(qty_questionmark_directory)
    features.append(qty_equal_directory)
    features.append(qty_at_directory)
    features.append(qty_and_directory)
    features.append(qty_exclamation_directory)
    features.append(qty_space_directory)
    features.append(qty_tilde_directory)
    features.append(qty_comma_directory)
    features.append(qty_plus_directory)
    features.append(qty_asterisk_directory)
    features.append(qty_hashtag_directory)
    features.append(qty_dollar_directory)
    features.append(qty_percent_directory)
    features.append(directory_length)

#76-check shortening service
  s = "https"
  h = "http"
  concatenate = s + test_url
  try:
    if scheme_string == s:
      response = urlopen(test_url)
      final_url = response.geturl() 
      response_code = response.getcode() 
      if response_code == 302: #response_code will be 302 for redirects
        redirecting_url = 0 #redirected so this may a short url
    elif scheme_string == h:
      response = urlopen(test_url)
      final_url = response.geturl() 
      response_code = response.getcode() 
      if response_code == 302: #response_code will be 302 for redirects
        redirecting_url = 0 #redirected so this may be a short url
    else:
      response = urlopen(concatenate)
      final_url = response.geturl() 
      response_code = response.getcode() 
      if response_code == 302: #response_code will be 302 for redirects
        redirecting_url = 0 #redirected so this may a short url
    features.append(redirecting_url)
  except:
    redirecting_url = 1
    features.append(redirecting_url)


#75-check if URL has an ip address in its domain
  try:
    if ip.ip_address(netloc_part):  #if it has an ip address in the netloc component then 1  
      ip_included = 1
    features.append(asn_ip)
  except:
    ip_included = 0  #if not 0
    features.append(ip_included) #add having_IP_Address to list of features


  return features
@app.route('/send_url', methods=['POST'])
def send_url():
    resp_json = request.get_data()
    params = resp_json.decode()
    url = params.replace("url=", "")
    current_url=url
    print("currently viewing: " + current_url)
    features=featureExtraction(current_url)
    arr = np.array(features)
    arr = arr.reshape(1,-1)
    y_pred=model.predict_classes(arr)

    if(y_pred==0):
        print("The opened page is legit. Keep browsing!")
    else:
        print("The opened page could be a phishing website. Watch out!")
    return jsonify({'message': 'success!'}), 200

app.run(host='0.0.0.0', port=5000)
