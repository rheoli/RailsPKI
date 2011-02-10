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

class BackendController < ApplicationController
  wsdl_service_name 'Backend'
  
  web_service_scaffold :invoke

  def find_all_requests
    RaItem.find(:all).map { |ra| ra.id }
  end

  def find_request_by_id(_id)
    RaItem.find(_id)
  end

  def find_to_sign
    RaItem.find(:all, :conditions=>["state like ?", RaItem::STATE_SIGN_APPROVED])
  end

  def update_ra_item(_ca_item)
    return(false) if RaItem.update_ra_item(_ca_item).nil?
    true
  end

  def find_update(_type)
    res=[]
    type_c=nil
    type_c=User if _type=="User"
    type_c=Role if _type=="Role"
    type_c=AuthMethod if _type=="AuthMethod"
    return(res) if type_c.nil?
    type_c.find(:all).each do |entry|
      res<<UpdateResult.new(:id=>entry.id, :updated_on=>entry.updated_on)
    end
    return(res)
  end

  def update_entries(_type, _entries)
    type_c=nil
    type_c=User if _type=="User"
    type_c=Role if _type=="Role"
    type_c=CaDomain if _type=="CaDomain"
    type_c=AuthMethod if _type=="AuthMethod"
    return(res) if type_c.nil?
    _entries.each do |entry_s|
      entry=YAML.load(entry_s)
      u=type_c.find_by_id(entry["id"]) || type_c.new
      u.attributes=entry
      u.id=entry["id"]
      u.save
    end
    return(true)
  end

  def delete_entries(_type, _entries)
    type_c=nil
    type_c=User if _type=="User"
    type_c=Role if _type=="Role"
    type_c=CaDomain if _type=="CaDomain"
    type_c=AuthMethod if _type=="AuthMethod"
    return(res) if type_c.nil?
    _entries.each do |id|
      entry=type_c.find_by_id(id)
      entry.destroy if !entry.nil?
    end
    return(true)
  end

  def role_links(_id, _u_entries, _a_entries)
    role=Role.find_by_id(_id)
    return(false) if role.nil?
    role.users=[]
    _u_entries.each do |id|
      role.users<<User.find_by_id(id)
    end
    role.auth_methods=[]
    _a_entries.each do |id|
      role.auth_methods<<AuthMethod.find_by_id(id)
    end
    role.save
  end
end
