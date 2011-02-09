require 'digest/sha2'

class User < ActiveRecord::Base
  has_and_belongs_to_many :roles 

  validates_uniqueness_of :username
  
  serialize :email_cc

  def self.authenticate( username, password )
    user = User.find( :first, :conditions => ['username = ?', username] )
    (user.nil? or user.invalid_password?(password)) ? nil : user
  end
  
  def password=(_passwd)
    if _passwd!="*"
      salt = [Array.new(6){rand(256).chr}.join].pack("m").chomp
      self.password_salt, self.password_hash = salt, Digest::SHA256.hexdigest(_passwd+salt)
    else
      self.password_salt="*"
      self.password_hash="*"
    end
  end
  
  def invalid_password?(_password)
    return(true) if self.password_hash=="*"
    Digest::SHA256.hexdigest(_password + self.password_salt) != self.password_hash
  end

end