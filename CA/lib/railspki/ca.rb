#--
# Copyright (c) 2005-11 Stephan Toggweiler
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
require 'yaml'

module RailsPKI

  class CA
    
    ATTR_ORDER=%w{C ST L O OU CN UID emailAddress serialNumber}
    
    def initialize(_base)
      @base=_base
      @ca=nil
      @ca_key=nil
      @ca_crt=nil
    end
    
    def load(_name)
      raise "already loaded" unless @ca.nil?
      ca_yml="#{@base}/var/#{_name}/ca.yml"
      raise "no ca file found" unless File.exists?(ca_yml)
      @ca=YAML.load(File.open(ca_yml))
      @ca["name"]=_name
      @ca_crt=OpenSSL::X509::Certificate.new(@ca["crt"]) unless @ca["crt"].nil?
      @ca_key=OpenSSL::PKey::RSA.new(@ca["key"]) unless @ca["key"].nil?
    end
      
    def sign(_reqname)
      raise "no ca info" if @ca.nil?
      raise "no signing ca found" if @ca_key.nil?
      raise "no signing ca found" if @ca_crt.nil? and _reqname!="self"
      req_yml=nil
      if _reqname=="self"
        req_yml="#{@base}/var/#{@ca["name"]}/ca.yml"
      else
        %w{00_local 02_to_sign}.each do |d|
          r="#{@base}/var/#{@ca["name"]}/#{d}/#{_reqname}.yml"
p r
          if File.exists?(r)
            req_yml=r
            break
          end
        end
      end
      raise "no req yml found" if req_yml.nil?
      req_info=YAML::load(File.open(req_yml))
      req=OpenSSL::X509::Request.new(req_info["req"])
      
      crt=OpenSSL::X509::Certificate.new
      crt.version=2
      crt.serial=1
      crt.public_key=req.public_key
      dn=[]
      ATTR_ORDER.each do |attr|
        next if req_info["dn"][attr].nil?
        if req_info["dn"][attr].class==Array
          req_info["dn"][attr].each do |a|
            dn<<[attr, a]
          end
        end
        if req_info["dn"][attr].class==String
          dn<<[attr, req_info["dn"][attr]]
        end
      end
      crt.subject=OpenSSL::X509::Name.new(dn)
      if _reqname=="self"
        crt.issuer=crt.subject
      else
        crt.issuer=@ca_crt.subject
      end
      time_now=Time.at((Time.now.to_i/3600)*3600).gmtime
      crt.not_before=time_now
      duration=1
      duration=req_info["duration"].to_i unless req_info["duration"].nil?
      duration=1 if duration < 1
      crt.not_after=Time.gm(time_now.year+duration, time_now.month, time_now.day, time_now.hour+1)
      unless _reqname=="self"
        crt.not_after=@ca_crt.not_after if crt.not_after > @ca_crt.not_after
      end
      crt_ef=OpenSSL::X509::ExtensionFactory.new
      crt_ef.subject_certificate=crt
      if _reqname=="self"
        crt_ef.issuer_certificate=crt
      else
        crt_ef.issuer_certificate=@ca_crt
      end
      sign=@ca["sign"]
      unless req_info["self_sign"].nil?
        sign=req_info["self_sign"] if _reqname=="self" or File.directory?("#{@base}/var/#{_reqname}")
      end
      sign["critical"]||=[]
      unless sign.has_key?("basicConstraints")
        sign["basicConstraints"]=["CA:false"]
        sign["critical"]<<"basicConstraints"
      end
      sign.each do |k, v|
        next if k=="critical"
        next if k=="subjectAltName"
        crt.add_extension(crt_ef.create_extension(k, v.join(","), sign["critical"].include?(k)))
      end
      if sign["subjectAltName"].class==Array
        sign["subjectAltName"].each do |v|
          if v=="DNS:CN"
            if req_info["dn"].has_key?("CN")
              v="DNS:#{req_info["dn"]["CN"]}"
            else
              next
            end
          end
          req_info["alternative"]||=[]
          req_info["alternative"]<<v
        end
      end
      if req_info["alternative"].class==Array
        crt.add_extension(crt_ef.create_extension("subjectAltName", req_info["alternative"].join(","), false))
      end
      crt.serial=gen_serial unless _reqname=="self"
      crt.sign(@ca_key, OpenSSL::Digest::SHA1.new)
      req_info["crt"]=crt.to_pem
      serial_t=sprintf "%08x", crt.serial
      File.open("#{@base}/var/#{@ca["name"]}/03_signed/#{serial_t}.yml", "w") do |f|
        f.write req_info.to_yaml
      end
      File.unlink(req_yml)
      crt
    end
    
    def create(_name)
      raise "no ca file found" unless File.exists?(_name)
      @ca=YAML.load(File.open(_name))
      raise "no name defined" if @ca["name"].nil?
      raise "ca already exists" if File.directory?("#{@base}/var/#{@ca["name"]}")
      pkey=OpenSSL::PKey::RSA.new(@ca["bits"])
      @ca["key"]=pkey.to_pem
      req=gen_request(pkey, @ca["dn"])
      @ca["req"]=req.to_pem
      Dir.mkdir("#{@base}/var/#{@ca["name"]}")
      %w{00_local 01_sec_check 02_to_sign 03_signed 10_expired 11_revoked}.each do |d|
        Dir.mkdir("#{@base}/var/#{@ca["name"]}/#{d}")
      end      
      File.open("#{@base}/var/#{@ca["name"]}/ca.yml","w") do |f|
        f.write @ca.to_yaml
      end
      sign_ca=RailsPKI::CA.new(@base)
      crt=nil
      if @ca["parent"]=="self"
        sign_ca.load(@ca["name"])
        crt=sign_ca.sign("self")
      else
        key=@ca["key"]
        @ca.delete("key")
        File.open("#{@base}/var/#{@ca["parent"]}/00_local/#{@ca["name"]}.yml","w") do |f|
          f.write @ca.to_yaml
        end
        @ca["key"]=key
        sign_ca.load(@ca["parent"])
        crt=sign_ca.sign(@ca["name"])
      end
      @ca_crt=crt
      @ca["crt"]=crt.to_pem unless crt.nil?
      File.open("#{@base}/var/#{@ca["name"]}/ca.yml","w") do |f|
        f.write @ca.to_yaml
      end
    end
    
    def gen_crl
      crl=OpenSSL::X509::CRL.new
      crl.version=1
      crl.issuer=@ca_crt.subject
      crl.sign(@ca_key, OpenSSL::Digest::SHA1.new)
      time_now=Time.at((Time.now.to_i/60)*60+60).gmtime
      crl.last_update=time_now
      duration=10
      duration=@ca["crl_duration"].to_i unless @ca["crl_duration"].nil?
      duration=1 if duration<1
      crl.next_update=time_now+(duration*86400)
      File.open("#{@base}/var/#{@ca["name"]}/#{@ca["name"]}.crl","w") do |f|
        f.write crl.to_der
      end
    end
    
    def gen_request(_key, _dn)
      dn=[]
      _dn.each do |k,v|
        dn << [k, v, OpenSSL::ASN1::PRINTABLESTRING]
      end
      req=OpenSSL::X509::Request.new
      req.version = 0
      req.subject = OpenSSL::X509::Name.new(dn)
      req.public_key = _key.public_key
      req.sign(_key, OpenSSL::Digest::SHA1.new)
      req
    end
  
  protected
    def gen_serial
      serial=0
      bad_serial=true
      while bad_serial
        serial=(rand*65535*65535).to_i
        serial_t=sprintf "%08x", serial
        bad_serial=false
        %w{03_signed 10_expired 11_revoked}.each do |d|
          if File.exists?("#{@base}/var/#{@ca["name"]}/#{d}/#{serial_t}.yml")
            bad_serial=true
            break
          end
        end
      end
      serial_t=sprintf "%08x", serial
      File.open("#{@base}/var/#{@ca["name"]}/03_signed/#{serial_t}.yml", "w") do |f|
        f.write "reserved".to_yaml
      end
      serial
    end
        
  end
  
end
