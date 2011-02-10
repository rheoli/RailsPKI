#--
# Copyright (c) 2006-07 Stephan Toggweiler
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

class UpdateResult < ActionWebService::Struct
  member :id,         :int
  member :updated_on, :time
end

class BackendApi < ActionWebService::API::Base
  api_method :find_all_requests, :returns => [[:int]]
  api_method :find_entry_by_id, :expects => [:string, :int], :returns => [:string]
  api_method :set_item_state, :expects => [:int, :string], :returns => [:bool]
  api_method :find_to_sign, :returns => [[:string]]
  api_method :update_ra_item, :expects => [:string], :returns => [:bool]
  api_method :find_update, :expects => [:string], :returns => [[UpdateResult]]
  api_method :update_entries, :expects => [:string,[:string]], :returns => [:bool]
  api_method :delete_entries, :expects => [:string,[:int]], :returns => [:bool]
  api_method :role_links, :expects => [:int,[:int],[:int]], :returns => [:bool]
end

