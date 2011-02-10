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

require 'digest/sha2'

class User < ActiveRecord::Base
  has_and_belongs_to_many :roles 

  validates_uniqueness_of :username
  
  serialize :email_cc

  def self.authenticate( username, password )
    user = User.find( :first, :conditions => ['username = ?', username] )
    (user.nil? or user.invalid_password?(password)) ? nil : user
  end

  def password
    ""
  end
  
  def password=(_passwd)
    return if _passwd==""
    if _passwd!="*"
      salt = [Array.new(6){rand(256).chr}.join].pack("m").chomp
      self.password_salt, self.password_hash = salt, Digest::SHA256.hexdigest(_passwd+salt)
    else
      self.password_salt="*"
      self.password_hash="*"
    end
  end
  
  def invalid_password?(_password)
    return(false) if _password.nil?
    return(false) if self.password_salt.nil?
    return(true) if self.password_hash=="*"
    Digest::SHA256.hexdigest(_password + self.password_salt) != self.password_hash
  end

end
