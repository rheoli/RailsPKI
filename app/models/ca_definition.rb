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

class CaDefinition < ActiveRecord::Base
  serialize :dn
  serialize :dn_policy
  serialize :extensions
  serialize :config
  
  has_one :ca_definition

  attr_reader :ca_cert

  def ca_create(_yaml)
    File.open("/tmp/tree.yaml", "w", 0600) { |f| f.write _yaml["yaml"].read}
    ca_yaml=YAML.load(File.open("/tmp/tree.yaml"))
    p ca_yaml
    self.name=ca_yaml["name"]
    self.bits=ca_yaml["bits"].to_i
    self.dn=ca_yaml["dn"]
    self.dn_policy=ca_yaml["dn_policy"]
    self.extensions=ca_yaml["extensions"]
    self.config=ca_yaml["config"]
    self.version=1
    #oPKey = OpenSSL::PKey::RSA.new(ca_defs.bits)
    @ca_pkey=OpenSSL::PKey::RSA.new(self.bits)
    ca_req=OpenSSL::X509::Request.new
    ca_dn=Array.new
    dn_policy["sort_as"].each do |d|
      ca_dn << [d, dn[d], OpenSSL::ASN1::PRINTABLESTRING]
    end
    ca_req.version   =0
    ca_req.subject   =OpenSSL::X509::Name.new(ca_dn)
    ca_req.public_key=@ca_pkey.public_key
    ca_req.sign(@ca_pkey, OpenSSL::Digest::SHA1.new)
    sign_ca=CaDefinition.find(ca_definition_id) if ca_definition_id>0
    if sign_ca==nil then
      @ca_cert=ca_sign(ca_req)
    else
      @ca_cert=sign_ca.ca_sign(ca_req)
    end
    self.pubkey_pem=@ca_cert.to_pem
    self.privkey_pem=@ca_pkey.to_pem
  end
  
  def set_pubkey
    @ca_cert=OpenSSL::X509::Certificate.new(pubkey_pem) if pubkey_pem!=nil and pubkey_pem!=""
  end
  
  def set_privkey
    @ca_pkey=OpenSSL::PKey::RSA.new(privkey_pem) if privkey_pem!=nil and privkey_pem!=""
  end
  
  def ca_sign(_req, _duration=nil, _subject=nil)
    if _req.class!=OpenSSL::X509::Request and _req.class!=OpenSSL::Netscape::SPKI
      raise "wrong request type"
    end
    p _req.class
    if _req.class==OpenSSL::X509::Request and !_req.verify(_req.public_key) then
      raise "can't verify request"
    end
    set_privkey if @ca_pkey==nil and privkey_pem!=""
    set_pubkey  if @ca_cert==nil and pubkey_pem!=""
    cert=OpenSSL::X509::Certificate.new
    cert.version    = 2
    self_sign=false
    if @ca_cert==nil then
      cert.serial=1
      @ca_cert   =cert
      self_sign  =true
    else
      bad_serial=true
      while bad_serial
        s_serial=(Time.now.to_i-@ca_cert.not_before.to_i)%50000
        o_serial=RaItem.find(:first, :conditions => ["crt_serial=?", s_serial])
        bad_serial=false if o_serial==nil
        sleep 1.0 if bad_serial
      end
      cert.serial=s_serial
    end
    req_subject=Hash.new
    if _req.class==OpenSSL::X509::Request
      _req.subject.to_a.each do |s|
        req_subject[s[0]]=s[1]
      end
    end
    subject=Array.new
    sort_as=dn_policy["sort_as"]
    sort_as=dn_policy["sort_as_sign"] if dn_policy.has_key?("sort_as_sign")
    sort_as.each do |d|
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
    cert.issuer    =@ca_cert.subject
    cert.public_key=_req.public_key
    cert.not_before=Time.now
    _duration=(3600*24*365) if _duration==nil
    cert.not_after =cert.not_before+_duration
    cert_ef=OpenSSL::X509::ExtensionFactory.new
    cert_ef.subject_certificate=cert
    cert_ef.issuer_certificate =@ca_cert
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
    s_exts.each do |id, data|
      next if data[0]==nil
      critical=data[0]
      value=data[1]
      value="email:#{_subject["emailAddress"]}" if value=="email"
      value="DNS:#{req_subject["CN"]}" if value=="DNS:CN"
      cert.add_extension(cert_ef.create_extension(id, value, critical))
    end
    cert.sign(@ca_pkey, OpenSSL::Digest::SHA1.new)
    p cert
    return cert
  end
  
end
