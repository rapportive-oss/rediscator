Dir[File.join(File.dirname(__FILE__), '**', '*')].each {|file| require file.sub(/\.rb$/, '') }
