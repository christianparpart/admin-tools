#! /usr/bin/env lua
-- vim:ts=4

-- CONFIG_FILE = '/etc/conf.d/ipt';
CONFIG_FILE = '/etc/ipt.conf';
IPTABLES = 'sudo iptables';
SYSCTL = 'sudo sysctl';

fw = fw or {}

-- {{{ helper
fw.debug = true;
fw.dryrun = false;
phigh = '1024:65535';

-- merges a set of tables
function tmerge(...)
	local tables = {...};
	local r = {};

	for _, t in ipairs({...}) do
		for k, v in pairs(t) do
			r[k] = v;
		end
	end

	return r;
end

function iptables(...)
	local cmd = IPTABLES;

	for _, arg in ipairs({...}) do
		cmd = cmd .. ' ' .. tostring(arg);
	end

	if fw.debug then
		print(cmd);
	end

	if not(fw.dryrun) then
		os.execute(cmd);
	end
end

function chainExists(table, chain)
	local cmd = IPTABLES
			 .. ' -t ' .. table .. ' -L ' .. chain
			 .. ' &> /dev/null';

	return os.execute(cmd) == 0;
end
function test()
	if chainExists('filter', 'trash') then
		print('yes');
	else
		print('no');
	end
end

function sysctl(key, value)
	local cmd = SYSCTL .. ' ' .. key .. '=' .. tostring(value);
	cmd = cmd .. ' &>/dev/null';

	os.execute(cmd);
end

function prule(r)
	local append = function(t, k, v)
		if v ~= nil then
			t[#t + 1] = k;
			t[#t + 1] = v;
		end
	end
	local args = {};

	append(args, '-t', r.table);
	append(args, '-A', r.chain);
	append(args, '-i', r.ifname);
	append(args, '-o', r.ofname);
	append(args, '-s', r.source);
	append(args, '-d', r.destination);
	append(args, '-p', r.proto);
	append(args, '--sport', r.sport);
	append(args, '--dport', r.dport);

	if r.table == 'filter' then
		append(args, '-m state', '--state NEW');
	end

	append(args, '-j', r.target or 'ACCEPT');

	if r.topts ~= nil then
		args[#args + 1] = r.topts;
	end

	iptables(unpack(args));
end
-- }}}

-- {{{ rules
source = function(f, t)
	return {'fsrc', f, t};
end
destination = function(f, t)
	return {'fdst', f, t};
end
snat = function(to)
	return {'snat', to};
end
function masquerade(r)
	prule(tmerge(r, {target='MASQUERADE'}));
end
function any(r)
	prule(r);
end
function none(r)
	prule(tmerge(r, {target='DROP'}));
end
function drop(r)
	iptables('-j', 'DROP');
end
function trash(r)
	prule(tmerge(r, {target='trash'}));
end
function established(r)
	r.topts = '-m state --state ESTABLISHED,RELATED';
	prule(r);
	r.topts = nil;
end
function ssh(r)
	prule(tmerge(r, {proto='tcp', sport=phigh, dport=22}));
end
function http(r)
	prule(tmerge(r, {proto='tcp', sport=phigh, dport=80}));
end
function http_alt(r)
	prule(tmerge(r, {proto='tcp', sport=phigh, dport=8080}));
end
function https(r)
	prule(tmerge(r, {proto='tcp', sport=phigh, dport=443}));
end
function openvpn(r)
	prule(tmerge(r, {proto='tcp', sport=phigh, dport=1194}));
end
function ping(r)
	prule(tmerge(r, {proto='icmp', topts='--icmp-type echo-request'}));
end
function dns(r)
	prule(tmerge(r, {proto='udp', sport=phigh, dport=53}));
	prule(tmerge(r, {proto='tcp', sport=phigh, dport=53}));
end
function mail(r)
	prule(tmerge(r, {proto='tcp', sport=phigh, dport=25}));
end
function dhcp(r)
	prule(tmerge(r, {proto='udp', sport=phigh, dport='67:68'}));
end
function teamspeak(r)
	prule(tmerge(r, {proto='udp', sport=phigh, dport='8767'}));
	prule(tmerge(r, {proto='tcp', sport=phigh, dport='14534'}));
	prule(tmerge(r, {proto='tcp', sport=phigh, dport='51234'}));
end
-- }}}

-- default config
prerouting = {}
input = { lo = any }
forward = {}
output = { lo = any }
postrouting = {}

-- override default config with administrator's wishes
dofile(CONFIG_FILE);

-----------------------------------------------------------------------------
function fw:process(chain, cname, table)
	local chain = chain or {}
	local extractIface = function(ifname)
		local iface = ifname:match('%w+');
		local oface = ifname:match('-(%w+)');
		return iface, oface;
	end

	if table == 'filter' then
		iptables('-t', table, '-A', cname, '-m state --state ESTABLISHED,RELATED -j ACCEPT');
	end

	for ifname, rules in pairs(chain) do
		local r = {};
		r.table = table;
		r.chain = cname;

		local iface, oface = extractIface(ifname);

		-- decide wether ifname is input interface name or output interface name.
		-- always allow already established connections on {table, chain, iface}
		if cname == 'OUTPUT' or cname == 'POSTROUTING' then
			r.ofname = iface;
		else
			r.ifname = iface;
			r.ofname = oface;
		end

		if type(rules) == 'table' then
			for _, rule in pairs(rules) do
				local t = tmerge(r);
				t.rule = rule;
				self:processRule(t);
			end
		elseif type(rules) == 'function' then
			r.rule = rules;
			self:processRule(r);
		end
	end

	if table == 'filter' then
		iptables('-t', 'filter', '-A', cname, '-j', 'trash');
	end
end

function fw:processRule(r)
	if type(r.rule) == 'function' then
		r.rule(r);
	elseif type(r.rule) == 'table' then
		local id = r.rule[1];
		local arg = r.rule[2];
		local rules = r.rule[3] or {};

		local t = tmerge(r);

		if id == 'fsrc' then
			t.source = arg;
		elseif id == 'fdst' then
			t.destination = arg;
		elseif id == 'snat' then
			t.target = 'SNAT';
			t.topts = '--to-source ' .. arg;
			sysctl('net.ipv4.ip_forward', 1);
			sysctl('net.ipv6.ip_forward', 1);
			return prule(tmerge(t, {'--to-source', arg}));
		else
			print('internal error: unknown rule filter');
		end

		for _, rule in pairs(rules) do
			t.rule = rule;
			self:processRule(t);
		end
	end
end

fw.start = function(self)
	self:cleanup('DROP');

	iptables('-t', 'filter', '-N', 'trash');
	iptables('-t', 'filter', '-A', 'trash', '-j', 'LOG', '--log-prefix', '"trash: "');
	iptables('-t', 'filter', '-A', 'trash', '-j', 'DROP');

	self:process(input, 'INPUT', 'filter');
	self:process(output, 'OUTPUT', 'filter');
	self:process(forward, 'FORWARD', 'filter');

	self:process(prerouting, 'PREROUTING', 'nat');
	self:process(postrouting, 'POSTROUTING', 'nat');
end

fw.stop = function(self)
	self:cleanup('ACCEPT');
end

fw.cleanup = function(self, p)
	local reset = function(table, chain)
		iptables('-t', table, '-F', chain);
		if table == 'filter' then iptables('-t', table, '-P', chain, p); end
	end
	local rr = {
		['filter'] = { 'INPUT', 'FORWARD', 'OUTPUT' },
		['nat'] = { 'PREROUTING', 'OUTPUT', 'POSTROUTING' },
		['mangle'] = { 'PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING' }
	}
	for table, chains in pairs(rr) do
		for _, chain in pairs(chains) do
			reset(table, chain);
		end
	end
	if chainExists('filter', 'trash') then
		iptables('-t filter -F trash');
		iptables('-t filter -X trash');
	end
end

fw.status = function(self)
	os.execute('echo ==== filter =================================================================');
	iptables('-t filter -L -v -n');
	os.execute('echo ==== nat ====================================================================');
	iptables('-t nat -L -v -n');
	os.execute('echo ==== mangle =================================================================');
	iptables('-t mangle -L -v -n');
end

function main(args)
	if args[1] == "start" then
		fw:start();
	elseif args[1] == "stop" then
		fw:stop();
	elseif args[1] == "status" then
		fw:status();
	else
		test();
	end
end

main({...})
