local httpspider = require "httpspider"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local tab = require "tab"
local table = require "table"

description = [[
Spiders a web site to gather information about its cookies.
]]

---
-- @usage
-- nmap -p 80 --script http-cookies <ip>
-- nmap -p 443 --script http-cookies <ip>
--
-- @output
-- PORT STATE SERVICE
-- 80/tcp openhttp
-- | http-auth-finder:
-- | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=as.com
-- |   Name   Domain   Value  Expires                        Path  Secure  Http-Only
-- |   hpage  .as.com  ES|0   Thu, 19-Oct-2017 07:56:39 GMT  /     nil     true
--
-- @args http-auth-finder.maxdepth the maximum amount of directories beneath
--       the initial url to spider. A negative value disables the limit.
--       (default: 3)
-- @args http-auth-finder.maxpagecount the maximum amount of pages to visit.
--       A negative value disables the limit (default: 20)

author = "Ernesto Fernandez"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = nil
currentDate = os.date("%x")

if (shortport.http) then
	portrule = shortport.http
elseif (shortport.ssl) then
	portrule = shortport.ssl
else
	return
end

local function headerContainsCookies(resp)
	local set_cookie = resp.header["set-cookie"]
	if (not(set_cookie)) then
		return false, "Server returned no cookies."
	end

	return true, "Server returned some cookies"
end

local function stringMonthToNumber(month)
	number = nil	
	if (month == "Jan") then
		number = 1
	elseif (month == "Feb") then
		number = 2
	elseif (month == "Mar") then
		number = 3
	elseif (month == "Apr") then
		number = 4
	elseif (month == "May") then
		number = 5
	elseif (month == "Jun") then
		number = 6
	elseif (month == "Jul") then
		number = 7
	elseif (month == "Ago") then
		number = 8
	elseif (month == "Sep") then
		number = 9
	elseif (month == "Oct") then
		number = 10
	elseif (month == "Nov") then
		number = 11
	elseif (month == "Dec") then
		number = 12
	else
		error("This month does not exist: " .. month)
	end

	return number
end

local function checkLongExpirationDate(date)

	local longExpiration = nil

	-- We eliminate the unwanted values
	if (string.sub(date, 15, 15) == " ") then
		date = string.sub(date, 6, 15)
	else
		if (string.sub(date, 13, 13) == "1") then
			return false
		else
			date = string.sub(date, 6, 12) .. string.sub(date, 15, 17)
		end
	end

	-- If the current year is lower than the cookie expiration year,
	-- then we have to check the month. If it is equal, the expiration
	-- date is less than a year. If it is 2 or more years greater,
	-- we have not to chech any more
	if ((tonumber(string.sub(currentDate, string.len(currentDate) - 1)) + 1) < tonumber(string.sub(date, string.len(date) - 2))) then
		longExpiration = true
	elseif (tonumber(string.sub(currentDate, string.len(currentDate) - 1)) < tonumber(string.sub(date, string.len(date) - 2))) then
		-- If the current month is equal than the cookie expiration month,
		-- then we have to check the day.
		if (tonumber(string.sub(currentDate, 1, 2)) < tonumber(stringMonthToNumber(string.sub(date, 4, 6)))) then
			longExpiration = true
		elseif (tonumber(string.sub(currentDate, 1, 2)) == tonumber(stringMonthToNumber(string.sub(date, 4, 6)))) then
			-- If the day is equal or greater, the expiration date is more than a year
			if(tonumber(string.sub(currentDate, 4, 5)) <= tonumber(string.sub(date, 1, 2))) then
				longExpiration = true
			else
				longExpiration = false
			end
		else
			longExpiration = false
		end
	else
		longExpiration = false
	end
	
	return longExpiration
end

action = function(host, port)

	-- create a new crawler instance
 	local crawler = httpspider.Crawler:new( host, port, nil, { scriptname = SCRIPT_NAME } )

	if (not(crawler)) then
		return
	end

	-- create a table entry in the registry
	nmap.registry.auth_urls = nmap.registry.auth_urls or {}
	crawler:set_timeout(10000)

	local cookiesTab = tab.new(2)
	tab.addrow(cookiesTab, "Name", "Domain", "Value", "Expires", "Path", "Secure", "Http-Only")
	while(true) do
		local status, r = crawler:crawl()
		-- if the crawler fails it can be due to a number of different reasons
		-- most of them are "legitimate" and should not be reason to abort
		if (not(status)) then
			if (r.err) then
				return stdense.format_output(false, r.reason)
			else
				break
			end
		end
		
		if (r.response.header) then
			local status, response = headerContainsCookies(r.response)
			if(status) then
				for i, cookie in pairs(r.response.cookies) do
					--for k, v in pairs(cookie) do
					--	print(k, v)
					--end
					if(cookie["expires"] ~= nil) then
						if (checkLongExpirationDate(cookie["expires"])) then
							tab.addrow(cookiesTab, cookie["name"], cookie["domain"], cookie["value"], cookie["expires"], cookie["path"], cookie["secure"], cookie["httponly"])
						end
					end
				end
			else
				return response
			end
		else
			return "There is no header"
		end
	
	end
	local result = { tab.dump(cookiesTab) }
	result.name = crawler:getLimitations()
	return stdnse.format_output(true, result)
end
