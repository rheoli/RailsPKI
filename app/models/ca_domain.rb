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

require 'yaml'

class CaDomain < ActiveRecord::Base
  
  serialize :dn
  serialize :dn_policy
  serialize :extensions
  serialize :config
  
  belongs_to :ca_domain
  has_many   :ca_domains
  has_many   :ca_items
  has_many   :ra_items
  
  validates_presence_of :yaml, :ca_domain_id

  attr_reader :ca_cert
  
  def pubkey
    if @ca_cert.class!=OpenSSL::X509::Certificate
      @ca_cert=nil
      @ca_cert=OpenSSL::X509::Certificate.new(pubkey_pem) if pubkey_pem!=nil and pubkey_pem!=""
    end
    @ca_cert
  end
  
  def pubkey=(_ca_cert)
    if _ca_cert.class==OpenSSL::X509::Certificate
      @ca_cert=_ca_cert
    end
  end
  
  def privkey
    if @ca_pkey.class!=OpenSSL::PKey::RSA
      @ca_pkey=OpenSSL::PKey::RSA.new(privkey_pem) if privkey_pem!=nil and privkey_pem!=""
    end
    @ca_pkey
  end
  
  def privkey=(_ca_pkey)
    if _ca_pkey.class==OpenSSL::PKey::RSA
      @ca_pkey=_ca_pkey
    end
  end
  
  def dn_sort_for_sign
    return(self.dn_policy["sort_as_sign"]) if self.dn_policy.has_key?("sort_as_sign")
    return(self.dn_policy["sort_as"])
  end
  
  def sign(_req, _duration=nil, _subject=nil, _extensions=nil)
    if _req.class!=OpenSSL::X509::Request and _req.class!=OpenSSL::Netscape::SPKI
      raise "wrong request type"
    end
    if _req.class==OpenSSL::X509::Request and !_req.verify(_req.public_key) then
      raise "can't verify request"
    end
    cert=OpenSSL::X509::Certificate.new
    cert.version    = 2
    self_sign=false
    if pubkey==nil then
      cert.serial=1
      self.pubkey=cert
      self_sign  =true
    end
    req_subject=Hash.new
    if _req.class==OpenSSL::X509::Request
      _req.subject.to_a.each do |s|
        req_subject[s[0]]=s[1]
      end
    end
    subject=Array.new
    dn_sort_for_sign.each do |d|
      data=nil
      if dn_policy["dn_info"][d][0][0]=="match" then
        if dn_policy["dn_info"][d][0][1]=="_issuer" then
          data=dn[d]
        else
          data=dn_policy["dn_info"][d][0][1]
        end
      else
        if _subject!=nil and _subject[d]!=nil then
          data=_subject[d]
        else
          data=req_subject[d]
        end
      end
      subject<<[d, data, OpenSSL::ASN1::PRINTABLESTRING] if data!=nil
    end
    cert.subject   =OpenSSL::X509::Name.new(subject)
    cert.issuer    =pubkey.subject
    cert.public_key=_req.public_key
    cert.not_before=Time.now
    _duration=(3600*24*365) if _duration==nil
    cert.not_after =cert.not_before+_duration
    cert_ef=OpenSSL::X509::ExtensionFactory.new
    cert_ef.subject_certificate=cert
    cert_ef.issuer_certificate =pubkey
    if config!=nil
      cert_config=OpenSSL::Config.new
      cert_config.add_value("", "oid_section", "addoid")
      config.each do |id, data|
        cert_config[id]=data
      end
      cert_ef.config = cert_config
    end
    s_exts={}
    s_exts_type=["default"]
    s_exts_type<<"self" if self_sign
    s_exts_type<<"sign" if !self_sign
    s_exts_type.each do |s|
      if extensions[s]!=nil then
        extensions[s].each do |id, data|
          s_exts[id]=data
        end
      end
    end
    if _extensions!=nil
      _extensions.each do |id, data|
        s_exts[id]=data
      end
    end
    is_subca_cert=false
    s_exts.each do |id, data|
p id
p data
      next if data[0]==nil or data[0]==""
      critical=data[0]
      value=data[1]
      value="email:#{req_subject["emailAddress"]}" if value=="email"
      value="DNS:#{req_subject["CN"]}" if value=="DNS:CN"
      cert.add_extension(cert_ef.create_extension(id, value, critical))
      is_subca_cert=true if id=="basicConstraints" and value=="CA:TRUE" and critical
    end
    if !self_sign
      s_serial=0
      if is_subca_cert
        ca_domains.each do |c|
          s_serial=c.pubkey.serial+1
        end
        s_serial=pubkey.serial*256+1 if s_serial==0
      else
        bad_serial=true
        while bad_serial
          s_serial=((Time.now.to_i-pubkey.not_before.to_i)%65535)+(pubkey.serial*65536)
          o_serial=RaItem.find(:first, :conditions => ["crt_serial=?", s_serial])
          bad_serial=false if o_serial==nil
          sleep 1.0 if bad_serial
        end
      end
      raise "no serial number found" if s_serial==0
      cert.serial=s_serial
    end
    cert.sign(privkey, OpenSSL::Digest::SHA1.new)
    return cert
  end

 protected
  def validate
    if !self.id.nil?
      self.pubkey_pem="" if self.pubkey_pem.nil?
      self.privkey_pem="" if self.privkey_pem.nil?
      if self.pubkey_pem==""
        errors.add("pubkey_pem", "can't be null")
      end
      if self.privkey_pem==""
        errors.add("privkey_pem", "can't be null")
      end
    end
  end

  def is_ca?
    is_ca=false
    begin
      if self.extensions["default"]["basicConstraints"][1]=="CA:TRUE"
        is_ca=true
      end
    rescue
    end
    is_ca
  end
 
  def after_validation_on_create
    ca_yaml=YAML.load(self.yaml)
    self.name=ca_yaml["name"]
    self.bits=ca_yaml["bits"].to_i
    self.dn=ca_yaml["dn"]
    self.dn_policy=ca_yaml["dn_policy"]
    self.extensions=ca_yaml["extensions"]
    self.config=ca_yaml["config"]
    self.version=1
    if !self.pubkey_pem.nil? and !self.privkey_pem.nil?
      return
    end
    self.privkey=OpenSSL::PKey::RSA.new(self.bits)
    ca_req=OpenSSL::X509::Request.new
    ca_dn=Array.new
    dn_policy["sort_as"].each do |d|
      ca_dn << [d, dn[d], OpenSSL::ASN1::PRINTABLESTRING]
    end
    ca_req.version   =0
    ca_req.subject   =OpenSSL::X509::Name.new(ca_dn)
    ca_req.public_key=privkey.public_key
    ca_req.sign(privkey, OpenSSL::Digest::SHA1.new)
    sign_ca=CaDomain.find(ca_domain_id) if ca_domain_id>0
    duration=ca_yaml["duration"]
    if !duration.nil?
      duration*=(3600*24*365)
    end
    if sign_ca==nil then
      pubkey=sign(ca_req, duration)
    else
      exts=nil
      exts=self.extensions["default"] if is_ca?
      pubkey=sign_ca.sign(ca_req, duration, nil, exts)
    end
    self.pubkey_pem=pubkey.to_pem
    self.privkey_pem=privkey.to_pem
  end
  
end
