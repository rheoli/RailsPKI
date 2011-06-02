require 'gettext/utils'
desc "Create mo-files for L10n" 
task :makemo do
  GetText.create_mofiles(true, "po", "locale")
end
