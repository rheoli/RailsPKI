require 'net/ldap'
require 'sha1'
require 'base64'

module ActiveRecord
  class BaseWithLdap < Base
    self.abstract_class = true
    
    def create_or_update
      errors.empty?
    end

    def object_class
      @object_class
    end

    def object_class=(_oc)
      @object_class=_oc
    end

    def set_password(_new_pwd)
      LDAP::Conn.new(@@config["Base"]["host"], @@config["Base"]["port"]).bind(@@config["Base"]["bind_dn"], @@config["Base"]["password"]) do |conn|
        #dn="#{@@config[self]["id"]}=#{self.attributes[@@config[self]["id"]]},#{@@config[self]["base"]}"
        hashed_pwd = "{SHA}" + Base64::encode64( SHA1.new(_new_pwd).digest ).chomp
        mod={"userpassword"=>[hashed_pwd]}
        conn.modify(self.dn, mod)
      end
    end

    def destroy
      ret=false
      LDAP::Conn.new(@@config["Base"]["host"], @@config["Base"]["port"]).bind(@@config["Base"]["bind_dn"], @@config["Base"]["password"]) do |conn|
        conn.delete(self.dn)
        ret=true
      end
      ret
    end

    def mysave
      ret=false
      LDAP::Conn.new(@@config["Base"]["host"], @@config["Base"]["port"]).bind(@@config["Base"]["bind_dn"], @@config["Base"]["password"]) do |conn|
        if @new_record
          add={}
          self.dn="#{@@config[self]["id"]}=#{self.attributes[@@config[self]["id"]]},#{@@config[self]["base"]}"
          self.attributes.each do |key, val|
            next if key=="dn"
            add[key]=[val.to_s] if val.class!=Array
            add[key]=val if val.class==Array
          end
          add["objectClass"]=['top', @@config[self]["class"]]
          conn.add(self.dn, add)
          ret=true
        else
          mod={}
          self.attributes.each do |key, val|
            next if key=="dn"
            next if val.nil?
            next if val=="" or (val.class==Array and val[0]=="")
            mod[key]=[val.to_s] if val.class!=Array
            mod[key]=val if val.class==Array
          end
          conn.modify(self.dn, mod)
          ret=true
        end
      end
      ret
    end
   
    def no_new_record!
      @new_record=false
    end
 
    class << self

      @@config={}

      def configuration(_key)
        return if _key.nil?
        @@config["Base"]={} if @@config["Base"].nil?
        _key.each do |key, val|
          @@config["Base"][key]=val
        end
      end

     def ldap_search(_key)
        return if _key.class!=Hash
        @@config[self]={} if @@config[self].nil?
        if _key[:base]
          @@config[self]["base"]=_key[:base]
        end
        if _key[:class]
          @@config[self]["class"]=_key[:class]
        end
        if _key[:id]
          @@config[self]["id"]=_key[:id]
        end
      end

      def find_first(_search)
        r=find(_search)
        return(nil) if r==[]
        r[0]
      end

      def passwd_ok?(_user, _passwd)
        return(false) if !(_user=~/^[A-Za-z0-9]+$/)
        res=false
        bind_dn="#{@@config[self]["id"]}=#{_user},#{@@config[self]["base"]}"
        begin
          LDAP::Conn.new(@@config["Base"]["host"], @@config["Base"]["port"]).bind(bind_dn, _passwd) do |conn|
            res=true
          end
        rescue LDAP::ResultError
        end
        res
      end

      def method_missing(method_id, *arguments)
        if match = /^find_(all_by|by)_([_a-zA-Z]\w*)$/.match(method_id.to_s)
          find({$2 => arguments[0]})
        else
          super
        end
      end

      def find(_search)
        if _search.class==String
          _search={@@config[self]["id"] => _search}
        end
        person_array=[]
        LDAP::Conn.new(@@config["Base"]["host"], @@config["Base"]["port"]).bind(@@config["Base"]["bind_dn"], @@config["Base"]["password"]) do |conn|
          search_base=@@config["Base"]["base"]
          search_base||=@@config[self]["base"]
          search_attr=self.column_names
          search_attr<<"objectClass"
          search_filter="(objectClass=#{@@config[self]["class"]})"
          _search.each do |key, val|
            search_filter << "(#{key}=#{val})"
          end
          res=conn.search2(search_base, LDAP::LDAP_SCOPE_SUBTREE, "(&#{search_filter})", self.column_names )
          res.each do |r|
            #p=self.allocate
            p=self.new
            p.no_new_record!
            myattr={}
            r.each do |attr, val|
              if attr.downcase=="objectclass"
                p.object_class=val
                next
              end
              if val.size==1 and columns_hash[attr.to_s.downcase].type!=:text
                myattr[attr.to_s.downcase]=val[0]
              else
                myattr[attr.to_s.downcase]=val
              end
            end
            columns_hash.each do |name, data|
              myattr[name]=[] if data.type==:text and myattr[name].nil?
            end
            p.attributes=myattr
            person_array<<p
          end
        end
        person_array
      end

      def columns()
        @columns ||= []
      end
      
      def column(name, sql_type = nil, default = nil, null = true)
        columns << ActiveRecord::ConnectionAdapters::Column.new(name.to_s, default, sql_type.to_s, null)
      end
    end
  end
end
