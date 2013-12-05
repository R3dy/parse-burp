#!/usr/bin/env ruby
# Copyright (C) 2013 www.pentestgeek.com Royce Davis (@r3dy__)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>
# #
require 'nokogiri'

# Display if no arguments are passed
unless ARGV.length > 0
  puts "Parse Burpsuite XML output into Tab delimited results"
  puts "Example: ./parse-brup.rb <xml-file> > output.csv\r\n\r\n"
  exit!
end

# Create an XML object from the file provided at runtime
report = Nokogiri::XML(File.open(ARGV[0]))

# This is just a string that serves as the title line of the CSV output
@title = "Assessment Phase\t" + 
  "Finding ID\t" +
  "Criticality\t" +
  "Confirmation_Status\t" +
  "Web_Application_URI\t" +
  "Web_Application_Path\t" +
  "Details\t" +
  "Finding_Title\t" +
  "Description\t" +
  "Recommendation\t" +
  "Banner\t" +
  "OS\t" +
  "WebServer\t" +
  "Technologies"

# This is the main parseing method which will run on each 
# finding in 'issue' (or finding) in the burp XML file.
def clean_finding(finding)
  output = ""
  output << "Web Application Findings\t"
  output << "\t"
  output << finding.css('severity').text + "\t"
  output << "Open\t"
  output << finding.css('host').text + "\t"
  output << finding.css('path').text + "\t"
  output << finding.css('issueDetail').text + "\t"
  output << finding.css('name').text + "\t"
  output << finding.css('issueBackground').text + "\t"
  output << finding.css('remediationBackground').text + "\t"
  if finding.css('response').text.include?("Server:")
    output << finding.css('response').text.split("Server: ")[1].split("\n")[0] + "\t"
  else
    output << "\t"
  end
  output << "\t\t\t"
  return output
end

puts @title
#Iterate through the XML file and send every issue 
# to the 'clean_finding' method
report.xpath('//issues/issue').each do |finding|
  puts clean_finding(finding)
end
