#--
# Copyright (c) 2006 Stephan Toggweiler
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#++

require 'openssl'

class RaAdminController < ApplicationController
  #layout "ra"
  
  #before_filter :authorize
  
  def index
  end
  
  def get_last_update_from_users
    get_last_update(User)
  end
  
  def get_last_update_from_roles
    get_last_update(Role)
  end
  
  def update_users
    update_model(User)
  end
  
 protected
 
  def update_model(_model)
    if method.get?
      send_data("access denied", :type=>"application/x-railspki-error")
      return
    end
    store=OpenSSL::X509::Store.new
    store.add_file(RAILS_ROOT+"/config/ssl/ca.crt")
    v7=OpenSSL::PKCS7::PKCS7.new(request.raw_post)
    p v7.verify(
          [OpenSSL::X509::Certificate.new(File.read('superuser.crt'))],
          store)
    p v7.error_string
    p v7.data
  end
 
  def get_last_update(_model)
    a=[]
    _model.find_all.each do |m|
      a<<[m.id, m.updated_on]
    end
    sign_and_send(a.to_yaml)
  end

  def sign_and_send(_text)
    p7 = OpenSSL::PKCS7.sign(
          OpenSSL::X509::Certificate.new(File.read(RAILS_ROOT+"/config/ssl/superuser.crt")), 
          OpenSSL::PKey::RSA.new(File.read(RAILS_ROOT+"/config/ssl/superuser.key")), 
          _text)
    send_data(p7.to_s, :type=>"application/x-railspki-signed-yaml")
  end

end
