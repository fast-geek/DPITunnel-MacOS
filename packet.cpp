#include "packet.h"
#include "utils.h"

#include <regex>
#include <map>

void parse_header(const std::string& line, std::map<std::string, std::string> & http_message) {
	if(line.empty()) return;

	size_t posFirst = line.find(':',0); //Look for separator ':'

	std::string key = line.substr(0, posFirst);
	transform(key.begin(), key.end(), key.begin(),
			  [](unsigned char c){ return std::tolower(c); });
	std::string value = line.substr(line.at(posFirst + 1) == ' ' ? posFirst + 2 : posFirst + 1); // Skip ' ' after header

	http_message[key] = value;
}

void parse_first_line(const std::string& line, std::map<std::string, std::string> & http_message) {
	size_t position, lpost;

	// Find request method
	position = line.find(' ');
	http_message["method"] = line.substr(0, position);
	lpost = ++position; //Skip character ' '

	// Find path
	position = line.find(' ', lpost);
	http_message["path"] = line.substr(lpost, (position-lpost));
	position++; //Skip character ' '

	// Find HTTP version
	http_message["version"] = line.substr(position);
}

std::map<std::string, std::string> parse_http_message(std::string message) {
	std::map<std::string, std::string> http_message;
	std::regex rgx("(\\r\\n|\\r|\\n)");
	std::sregex_token_iterator iter(message.begin(),
									message.end(),
									rgx,
									-1);
	std::sregex_token_iterator end;
	for ( bool is_first = true; iter != end; ++iter) {
		if(is_first) {
			parse_first_line(*iter, http_message);
			is_first = false;
			continue;
		}
		parse_header(*iter, http_message);
	}
	return http_message;
}


int parse_request(const std::string & request, std::string & method, std::string & host, int & port, bool is_proxy) {
	std::map<std::string, std::string> http_request = parse_http_message(request);

	if(http_request.find("method") == http_request.end())
		return -1;
	method = http_request["method"];

	std::string found_url;
	if(is_proxy) {
		// Extract hostname an port if exists
		std::string regex_string = "[-a-zA-Z0-9@:%._\\+~#=]{2,256}\\.[-a-z0-9]{1,16}(:[0-9]{1,5})?";
		std::regex url_find_regex(regex_string);
		std::smatch match;

		if(std::regex_search(http_request["path"], match, url_find_regex) == 0)
			return -1;

		// Get string from regex output
		found_url = match.str(0);
	} else {
		if(http_request.find("host") == http_request.end())
			return -2; // seems it is https in transparent mode
		found_url = http_request["host"];
	}

	// Remove "www." if exists
	size_t www = found_url.find("www.");
	if(www != std::string::npos)
		found_url.erase(www, 4);

	// Check if port exists
	size_t port_start_position = found_url.find(':');
	if(port_start_position == std::string::npos) {
		// If no set default port
		if(method == "CONNECT")	port = 443;
		else port = 80;
		host = found_url;
	} else {
		// If yes extract port
		port = std::stoi(found_url.substr(port_start_position + 1, found_url.size() - port_start_position));
		host = found_url.substr(0, port_start_position);
	}

	return 0;
}

void remove_proxy_strings(std::string & request, unsigned int & last_char) {
	std::string method, host;
	int port;
	if(parse_request(request, method, host, port, true) || !validate_http_method(method))
		return;

	unsigned int request_size = request.size();

	// Remove schema
	const std::string http_str("http://");
	if(last_char >= http_str.size() && request.find(http_str, method.size()) == method.size() + 1) {
		request.erase(method.size() + 1, http_str.size());
		last_char -= http_str.size();
	}

	// Remove www
	const std::string www_str("www.");
	if(last_char >= www_str.size() && request.find(www_str, method.size()) == method.size() + 1) {
		request.erase(method.size() + 1, www_str.size());
		last_char -= www_str.size();
	}

	// Remove domain
	if(last_char >= host.size() && request.find(host, method.size()) == method.size() + 1) {
		request.erase(method.size() + 1, host.size());
		last_char -= host.size();
	}

	// Remove port
	std::string port_str(":" + std::to_string(port));
	if(last_char >= port_str.size() && request.find(port_str, method.size()) == method.size() + 1) {
		request.erase(method.size() + 1, port_str.size());
		last_char -= port_str.size();
	}

	const std::string proxy_conn_str("Proxy-Connection: keep-alive\r\n");
	size_t proxy_connection_hdr_start = request.find(proxy_conn_str);
	if(last_char >= proxy_conn_str.size() && proxy_connection_hdr_start != std::string::npos) {
		request.erase(proxy_connection_hdr_start, proxy_conn_str.size());
		last_char -= proxy_conn_str.size();
	}

	request.resize(request_size, ' ');
}
