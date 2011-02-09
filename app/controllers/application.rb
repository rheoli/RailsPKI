#--
# Copyright (c) 2005-06 Stephan Toggweiler
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

class ApplicationController < ActionController::Base

 protected
 
  def current_user
    @current_user ||= session[:user] ? User.find_by_username(session[:user]) : nil
  end
  
  def current_role
    @current_role ||= session[:role] ? Role.find_by_id(session[:role]) : nil
  end
  
 private
 
  def redirect_to_access_denied(_info)
    flash[:notice]=_info
    redirect_to :controller => "auth", :action => "access_denied"
  end
 
  def authorize
    unless session[:user]
      flash[:notice] = "Please log in"
      session[:login_jumpto] = request.parameters
      redirect_to(:controller => "auth", :action => "login")
      return(false)
    end
    return(true)
  end
end
