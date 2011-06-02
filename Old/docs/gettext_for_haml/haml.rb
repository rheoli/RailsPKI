#===========================================================
#=begin
#  parser/haml.rb - parser for HAML
#
#  Copyright (C) 2007 Ivan Kerin
#
#  You may redistribute it and/or modify it under the same
#  license terms as Ruby.
#=end

require 'gettext/parser/ruby.rb'

module GetText
  module HamlParser
    @config = {
      :extnames => ['.haml']
    }

    module_function
    # Sets some preferences to parse ERB files.
    # * config: a Hash of the config. It can takes some values below:
    #   * :extnames: An Array of target files extension. Default is [".haml"].
    def init(config)
      config.each{|k, v|
        @config[k] = v
      }
    end

    def parse(file, targets = []) # :nodoc:
      file_lines = (IO.readlines(file).join)
      haml = file_lines.scan(/(\=|\-)([^>]{1}[^\n]*)\n/).collect{ | e, i | (i%2)}
      haml += file_lines.scan(/\n[^=-]+(\{[^\}]+\})/)

      RubyParser.parse_lines(file, haml, targets)
    end

    def target?(file) # :nodoc:
       @config[:extnames].each do |v|
	    return true if File.extname(file) == v
      end
      false
    end
  end
end

if __FILE__ == $0
  # ex) ruby glade.rhtml foo.rhtml  bar.rhtml
  ARGV.each do |file|
    p GetText::ErbParser.parse(file)
  end
end

