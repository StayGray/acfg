#!/usr/bin/python3

import os
import sys
import subprocess
import argparse
import ipaddress
import random
import qrcode

DEBUGFILE = False
DEBUGKEY = False

#
# Constants and defaults
#

minIPv4Octet = 1
maxIPv4Octet = 255

minIPv6GID1 = 0x00
maxIPv6GID1 = 0xff

minIPv6GID2 = 0x0000
maxIPv6GID2 = 0xffff

minIPv6GID3 = 0x0000
maxIPv6GID3 = 0xffff

minIPv6SID = 0x0000
maxIPv6SID = 0xffff

ipv6ULA = 0xfd00

minIpPort = 49152
maxIpPort = 65535

minJc =   3
maxJc = 127

minJmin =    3
maxJmin =  700
maxJmax = 1270

minSx =   3
maxSx = 127

minHx = 0x10000011
maxHx = 0x7FFFFF00

defaultConfigFileName = "./awg0.conf" if DEBUGFILE else "/etc/amnezia/amneziawg/awg0.conf"

prComment     = "#"
prHiddenParam = prComment + "=="
prStopParse   = prComment + "----"

defDNSv4 = "8.8.8.8"
defDNSv6 = "2001:4860:4860::8888"

defKeepalive = 60

# Section names

sectIface = "Interface"
sectPeer  = "Peer"

# top-level parameters

pNameExtAddr  = "ExtAddress"
pNameIPv4Tmpl = "IPv4Tmpl"
pNameIPv6Tmpl = "IPv6Tmpl"

# common parameters

pNamePrivKey    = "PrivateKey"
pNamePubKey     = "PublicKey"
pNameAllowedIPs = "AllowedIPs"

# Interface section parameters

pNameAddress    = "Address"
pNamePort       = "ListenPort"
pNameJc         = "Jc"
pNameJmin       = "Jmin"
pNameJmax       = "Jmax"
pNameS1         = "S1"
pNameS2         = "S2"
pNameH1         = "H1"
pNameH2         = "H2"
pNameH3         = "H3"
pNameH4         = "H4"

# Peer section parameters

pNameClName    = "ClientName"
pNameClId      = "ClientId"
pNameEndpoint  = "Endpoint"
pNameKeepalive = "PersistentKeepalive"
pNameDNS       = "DNS"

#
# Helpers
#

def execCmd(cmd: str, diag: str, instr: str = None) -> str:
    proc = subprocess.run(cmd, shell = True, input = instr, capture_output = True, encoding = "utf8")
    if proc.returncode:
        raise RuntimeError(diag)
    return proc.stdout.strip()

def genKeys() -> (str, str):
    if DEBUGKEY:
        return ("PRIVATE KEY HERE", "PUBLIC KEY HERE")
    privKey = execCmd("awg genkey", "Cannot generate private key")
    pubKey = execCmd("awg pubkey", "Cannot generate public key", privKey)
    return (privKey, pubKey)

def getServerIface() -> str:
    out = execCmd("ip link show", "Cannot get net interfaces")
    for line in out.split("\n"):
        if "BROADCAST" in line and "state UP" in line:
            return line.split(":")[1].strip()
    raise RuntimeError("Cannot find server interface")

def getExtAddress() -> str:
    return execCmd("curl -4 -s icanhazip.com", "Cannot get external IP address").strip()

#
# Config file wrapper
#

class CfgFileParam:
    def __init__(self, lineNum: int, value: str, hidden: bool):
        self.lineNum = lineNum
        self.value   = value
        self.hidden  = hidden

class CfgFileSection:
    def __init__(self, name: str, line: str = None):
        self.name   = name  # section name
        self.params = {}    # parameters
        # section text
        if line:
            self.lines = [ line ]
        elif name:
            self.lines = [ "[" + name + "]" ]
        else:
            self.lines = []

    def getParam(self, paramName: str) -> str:
        param = self.params.get(paramName)
        return param.value if param else None

    def getParamAssignString(self, paramName: str, paramVal: str, hidden: bool = False) -> str:
        prefix = prHiddenParam + " " if hidden else ""
        return prefix + paramName + " = " + paramVal

    def setParam(self, paramName: str, paramVal: str, hidden: bool = False) -> None:
        assignStr = self.getParamAssignString(paramName, paramVal, hidden)
        if paramName in self.params:
            paramData = self.params[paramName]
            if paramData.hidden != hidden:
                raise RuntimeError("Parameter type mismatch: '%s'" % paramName)
            paramData.value = paramVal
            self.lines[paramData.lineNum] = assignStr
        else:
            self.params[paramName] = CfgFileParam(len(self.lines), paramVal, hidden)
            self.lines.append(assignStr)

    def addLine(self, line: str = "") -> None:
        self.lines.append(line)

    def addText(self, text: str, subst: dict) -> None:
        for line in text.split("\n"):
            line = line.strip()
            for s in subst.items():
                line = line.replace(s[0], s[1])
            self.addLine(line)

    def dump(self, file) -> None:
        for line in self.lines:
            file.write(line + "\n")

    def toText(self) -> str:
        text = ""
        for line in self.lines:
            text += line + "\n"
        return text

class CfgFile(CfgFileSection):
    def __init__(self):
        CfgFileSection.__init__(self, None)
        self.sections = []  # list of sections

    def load(self, cfgFileName: str) -> None:
        lines = []
        with open(cfgFileName, "r") as file:
            lines = file.readlines()

        sect = self
        doParse = True
        for line in lines:
            line = line.removesuffix("\n")
            wrkLine = line.strip()

            if wrkLine[:1] == "[" and wrkLine[-1:] == "]":
                sect = CfgFileSection(wrkLine[1:-1], line)
                self.sections.append(sect)
                doParse = True
            else:
                if wrkLine.startswith(prStopParse):
                    doParse = False

                if doParse:
                    isHiddenParam = wrkLine.startswith(prHiddenParam)
                    isComment     = (not isHiddenParam) and wrkLine.startswith(prComment)
                    if isHiddenParam:
                        wrkLine = wrkLine.removeprefix(prHiddenParam).strip()
                    if not isComment and wrkLine.find("=") >= 0:
                        (paramName, paramVal) = [s.strip() for s in wrkLine.split("=", 1)]
                        if paramName:
                            sect.params[paramName] = CfgFileParam(len(sect.lines), paramVal, isHiddenParam)

                sect.lines.append(line)

    def addSection(self, name: str) -> CfgFileSection:
        sect = CfgFileSection(name)
        self.sections.append(sect)
        return sect

    def save(self, cfgFileName: str) -> None:
        with open(cfgFileName, "w") as file:
            self.dump(file)
            for sect in self.sections:
                sect.dump(file)

    def saveQRcode(self, cfgFileName: str) -> None:
        text = self.toText()
        for sect in self.sections:
            text += sect.toText()
        img = qrcode.make(text)
        img.save(cfgFileName)

    def findIface(self) -> CfgFileSection:
        for sect in self.sections:
            if sect.name == sectIface:
                return sect
        return None

    def findClient(self, clname: str) -> CfgFileSection:
        for sect in self.sections:
            if sect.name == sectPeer and sect.getParam(pNameClName) == clname:
                return sect
        return None

    def removeClient(self, clname: str) -> bool:
        for idx in range(len(self.sections)):
            sect = self.sections[idx]
            if sect.name == sectPeer and sect.getParam(pNameClName) == clname:
                del self.sections[idx]
                return True
        return False

    def getClientSections(self) -> list:
        sectList = []
        for sect in self.sections:
            if sect.name == sectPeer and sect.getParam(pNameClName):
                sectList.append(sect)
        return sectList

    def findNewClientId(self) -> int:
        # in fact, 1 is used as a server ID
        usedIds = { 1 }
        maxClientId = 1
        for sect in self.sections:
            if sect.name == sectPeer:
                clId = int(sect.getParam(pNameClId))
                usedIds.add(clId)
                if clId > maxClientId:
                    maxClientId = clId
        for id in range(2, maxClientId + 2):
            if id not in usedIds:
                return id
        return 0

#
# Command handlers
#

def handleConfig(args: argparse.Namespace) -> None:
    match args.cmd:
        case "create":
            ipv4Octet  = args.octet   if args.octet   else random.randint(minIPv4Octet, maxIPv4Octet)
            serverPort = args.port    if args.port    else random.randint(minIpPort, maxIpPort)
            ifaceName  = args.iface   if args.iface   else getServerIface()
            extAddr    = args.extaddr if args.extaddr else getExtAddress()
            doIPv6     = args.ipv6

            if ipv4Octet not in range(minIPv4Octet, maxIPv4Octet + 1):
                raise RuntimeError("IPv4 octet out of allowed range [%d..%d]" % (minIPv4Octet, maxIPv4Octet))
            if serverPort not in range(minIpPort, maxIpPort + 1):
                raise RuntimeError("server port out of allowed range [%d..%d]" % (minIpPort, maxIpPort))

            IPv4Tmpl = "192.168.%d.%%d" % ipv4Octet
            serverAddr = (IPv4Tmpl + "/24") % 1
            if doIPv6:
                IPv6GID1 = random.randint(minIPv6GID1, maxIPv6GID1)
                IPv6GID2 = random.randint(minIPv6GID2, maxIPv6GID2)
                IPv6GID3 = random.randint(minIPv6GID3, maxIPv6GID3)
                IPv6SID  = random.randint(minIPv6SID , maxIPv6SID )
                IPv6Tmpl = "%x:%x:%x:%x::%%d" % (ipv6ULA + IPv6GID1, IPv6GID2, IPv6GID3, IPv6SID)
                serverAddr += ", " + (IPv6Tmpl + "/64") % 1
            (privKey, pubKey) = genKeys()
            jmin = random.randint(minJmin, maxJmin)
            jmax = random.randint(jmin + 1, maxJmax)

            cfgFile = CfgFile()

            cfgFile.setParam(pNameExtAddr , extAddr , True)
            cfgFile.setParam(pNameIPv4Tmpl, IPv4Tmpl, True)
            cfgFile.setParam(pNameIPv6Tmpl, IPv6Tmpl, True)
            cfgFile.addLine()

            ifaceSection = cfgFile.addSection(sectIface)

            ifaceSection.setParam(pNamePubKey , pubKey                                , True)
            ifaceSection.setParam(pNamePrivKey, privKey                               )
            ifaceSection.setParam(pNameAddress, serverAddr                            )
            ifaceSection.setParam(pNamePort   , str(serverPort)                       )
            ifaceSection.setParam(pNameJc     , str(random.randint(minJc, maxJc))     )
            ifaceSection.setParam(pNameJmin   , str(jmin)                             )
            ifaceSection.setParam(pNameJmax   , str(jmax)                             )
            ifaceSection.setParam(pNameS1     , str(random.randint(minSx, maxSx))     )
            ifaceSection.setParam(pNameS2     , str(random.randint(minSx, maxSx))     )
            ifaceSection.setParam(pNameH1     , str(random.randint(minHx, maxHx))     )
            ifaceSection.setParam(pNameH2     , str(random.randint(minHx, maxHx))     )
            ifaceSection.setParam(pNameH3     , str(random.randint(minHx, maxHx))     )
            ifaceSection.setParam(pNameH4     , str(random.randint(minHx, maxHx))     )
            ifaceSection.addLine()
            ifaceSection.addLine(prStopParse)
            ifaceSection.addLine()
            ifaceSection.addText( \
                """PostUp = iptables -A INPUT -p udp --dport <SERVER_PORT> -m conntrack --ctstate NEW -j ACCEPT --wait 10 --wait-interval 50
                   PostUp = iptables -A FORWARD -i <SERVER_IFACE> -o %i -j ACCEPT --wait 10 --wait-interval 50
                   PostUp = iptables -A FORWARD -i %i -j ACCEPT --wait 10 --wait-interval 50
                   PostUp = iptables -t nat -A POSTROUTING -o <SERVER_IFACE> -j MASQUERADE --wait 10 --wait-interval 50
                   PostUp = ip6tables -A FORWARD -i %i -j ACCEPT --wait 10 --wait-interval 50
                   PostUp = ip6tables -t nat -A POSTROUTING -o <SERVER_IFACE> -j MASQUERADE --wait 10 --wait-interval 50""",
                {
                    "<SERVER_PORT>"  : str(serverPort),
                    "<SERVER_IFACE>" : ifaceName
                }
            )
            ifaceSection.addLine()
            ifaceSection.addText( \
                """PreDown = iptables -D INPUT -p udp --dport <SERVER_PORT> -m conntrack --ctstate NEW -j ACCEPT --wait 10 --wait-interval 50
                   PreDown = iptables -D FORWARD -i <SERVER_IFACE> -o %i -j ACCEPT --wait 10 --wait-interval 50
                   PreDown = iptables -D FORWARD -i %i -j ACCEPT --wait 10 --wait-interval 50
                   PreDown = iptables -t nat -D POSTROUTING -o <SERVER_IFACE> -j MASQUERADE --wait 10 --wait-interval 50
                   PreDown = ip6tables -D FORWARD -i %i -j ACCEPT --wait 10 --wait-interval 50
                   PreDown = ip6tables -t nat -D POSTROUTING -o <SERVER_IFACE> -j MASQUERADE --wait 10 --wait-interval 50""",
                {
                    "<SERVER_PORT>"  : str(serverPort),
                    "<SERVER_IFACE>" : ifaceName
                }
            )
            ifaceSection.addLine()

            cfgFile.save(configFileName)

        case "remove":
            if os.path.exists(configFileName):
                os.remove(configFileName)

        case "regen":
            cfgFile = CfgFile()
            cfgFile.load(configFileName)

            ifaceSect = cfgFile.findIface()
            if not ifaceSect:
                raise RuntimeError("Cannot find interface section")

            jmin = random.randint(minJmin, maxJmin)
            jmax = random.randint(jmin + 1, maxJmax)

            ifaceSect.setParam(pNameJc  , str(random.randint(minJc, maxJc)))
            ifaceSect.setParam(pNameJmin, str(jmin)                        )
            ifaceSect.setParam(pNameJmax, str(jmax)                        )
            ifaceSect.setParam(pNameS1  , str(random.randint(minSx, maxSx)))
            ifaceSect.setParam(pNameS2  , str(random.randint(minSx, maxSx)))
            ifaceSect.setParam(pNameH1  , str(random.randint(minHx, maxHx)))
            ifaceSect.setParam(pNameH2  , str(random.randint(minHx, maxHx)))
            ifaceSect.setParam(pNameH3  , str(random.randint(minHx, maxHx)))
            ifaceSect.setParam(pNameH4  , str(random.randint(minHx, maxHx)))

            cfgFile.save(configFileName)

def getSectionParam(sect: CfgFileSection, name: str, errstr: str) -> str:
    param = sect.getParam(name)
    if not param:
        raise RuntimeError(errstr)
    return param

def excludeSubnet(netRanges: list, subnet: ipaddress.IPv4Network) -> list:
    for idx in range(len(netRanges)):
        if subnet.subnet_of(netRanges[idx]):
            netRanges[idx:idx+1] = netRanges[idx].address_exclude(subnet)
    return netRanges

def generateAllowedIPs(doIPv6: bool, withLocal: bool) -> str:
    subnets = [ipaddress.IPv4Network("0.0.0.0/0")]
    if not withLocal:
        subnets = excludeSubnet(subnets, ipaddress.IPv4Network("10.0.0.0/8"))
        subnets = excludeSubnet(subnets, ipaddress.IPv4Network("172.16.0.0/12"))
        subnets = excludeSubnet(subnets, ipaddress.IPv4Network("192.168.0.0/16"))
    subnets.sort()
    if doIPv6:
        ipv6Subnets = [ipaddress.IPv6Network("::/0")]
        if not withLocal:
            ipv6Subnets = excludeSubnet(ipv6Subnets, ipaddress.IPv6Network("fc00::/7"))
        ipv6Subnets.sort()
        subnets += ipv6Subnets
    return ", ".join([str(s) for s in subnets])

def handleClient(args: argparse.Namespace) -> None:
    cfgFile = CfgFile()
    cfgFile.load(configFileName)
    match args.cmd:
        case "add":
            IPv4Tmpl = getSectionParam(cfgFile, pNameIPv4Tmpl , "Cannot find IPv4 template")
            IPv6Tmpl = cfgFile.getParam(pNameIPv6Tmpl)
            doIPv6 = IPv6Tmpl is not None

            modified = False
            for clName in args.clname:
                if cfgFile.findClient(clName):
                    print("Client '%s' already exists - skipping" % clName)
                else:
                    clId = cfgFile.findNewClientId()
                    clAddr = (IPv4Tmpl + "/32") % clId
                    if doIPv6:
                        clAddr += ", " + (IPv6Tmpl + "/128") % clId

                    (privKey, pubKey) = genKeys()

                    peerSection = cfgFile.addSection(sectPeer)

                    peerSection.setParam(pNameClName    , clName   , True)
                    peerSection.setParam(pNameClId      , str(clId), True)
                    peerSection.setParam(pNamePrivKey   , privKey  , True)
                    peerSection.setParam(pNamePubKey    , pubKey   )
                    peerSection.setParam(pNameAllowedIPs, clAddr   )
                    peerSection.addLine()

                    modified = True

            if modified:
                cfgFile.save(configFileName)

        case "remove":
            modified = False
            for clName in args.clname:
                if cfgFile.removeClient(clName):
                    modified = True
                else:
                    print("Client '%s' doesn't exist - skipping" % clName)

            if modified:
                cfgFile.save(configFileName)

        case "list":
            for sect in cfgFile.getClientSections():
                if args.long:
                    print("'%s' (%s): %s" % (sect.getParam(pNameClName), sect.getParam(pNameClId), sect.getParam(pNamePubKey)))
                else:
                    print("'%s'" % sect.getParam(pNameClName))

        case "generate":
            if len(args.clname) == 0 and not args.all:
                raise RuntimeError("No clients specified to generate configs for")

            if args.all:
                clNames = [sect.getParam(pNameClName) for sect in cfgFile.getClientSections()]
            else:
                clNames = args.clname
            if len(clNames) == 0:
                raise RuntimeError("No clients specified to generate configs for")

            extAddr  = getSectionParam(cfgFile, pNameExtAddr , "Cannot find server external address")
            IPv4Tmpl = getSectionParam(cfgFile, pNameIPv4Tmpl, "Cannot find IPv4 template"          )
            IPv6Tmpl = cfgFile.getParam(pNameIPv6Tmpl)
            doIPv6 = IPv6Tmpl is not None

            ifaceSect = cfgFile.findIface()
            if not ifaceSect:
                raise RuntimeError("Cannot find interface section")

            s1        = getSectionParam(ifaceSect, pNameS1    , "Cannot find S1 server parameter"  )
            s2        = getSectionParam(ifaceSect, pNameS2    , "Cannot find S2 server parameter"  )
            h1        = getSectionParam(ifaceSect, pNameH1    , "Cannot find H1 server parameter"  )
            h2        = getSectionParam(ifaceSect, pNameH2    , "Cannot find H2 server parameter"  )
            h3        = getSectionParam(ifaceSect, pNameH3    , "Cannot find H3 server parameter"  )
            h4        = getSectionParam(ifaceSect, pNameH4    , "Cannot find H4 server parameter"  )
            port      = getSectionParam(ifaceSect, pNamePort  , "Cannot find server port parameter")
            svrPubKey = getSectionParam(ifaceSect, pNamePubKey, "Cannot find server public key"    )

            for clName in clNames:
                clientSection = cfgFile.findClient(clName)
                if clientSection:
                    clId      = getSectionParam(clientSection, pNameClId   , "Cannot find client ID for '%s'" % clName  )
                    clAddr = (IPv4Tmpl + "/32") % int(clId)
                    if doIPv6:
                        clAddr += ", " + (IPv6Tmpl + "/128") % int(clId)
                    clPrivKey = getSectionParam(clientSection, pNamePrivKey, "Cannot find private key for '%s'" % clName)
                    clPubKey  = getSectionParam(clientSection, pNamePubKey , "Cannot find public key for '%s'" % clName )

                    jc   = random.randint(minJc, maxJc)
                    jmin = random.randint(minJmin, maxJmin)
                    jmax = random.randint(jmin + 1, maxJmax)
                    allowedStr = generateAllowedIPs(doIPv6, args.local)

                    if args.dns:
                        dnsServers = ", ".join(args.dns)
                    else:
                        dnsServers = (defDNSv4 + ", " + defDNSv6) if doIPv6 else defDNSv4

                    keepalive = args.keepalive if args.keepalive else defKeepalive

                    clCfgFile = CfgFile()

                    ifaceSection = clCfgFile.addSection(sectIface)

                    ifaceSection.setParam(pNamePubKey , clPubKey  , True)
                    ifaceSection.setParam(pNamePrivKey, clPrivKey )
                    ifaceSection.setParam(pNameAddress, clAddr    )
                    ifaceSection.setParam(pNameDNS    , dnsServers)
                    ifaceSection.setParam(pNameJc     , str(jc)   )
                    ifaceSection.setParam(pNameJmin   , str(jmin) )
                    ifaceSection.setParam(pNameJmax   , str(jmax) )
                    ifaceSection.setParam(pNameS1     , s1        )
                    ifaceSection.setParam(pNameS2     , s2        )
                    ifaceSection.setParam(pNameH1     , h1        )
                    ifaceSection.setParam(pNameH2     , h2        )
                    ifaceSection.setParam(pNameH3     , h3        )
                    ifaceSection.setParam(pNameH4     , h4        )
                    ifaceSection.addLine()

                    peerSection = clCfgFile.addSection(sectPeer)

                    peerSection.setParam(pNameAllowedIPs , allowedStr               )
                    peerSection.setParam(pNameEndpoint   , "%s:%s" % (extAddr, port))
                    peerSection.setParam(pNameKeepalive  , str(keepalive)           )
                    peerSection.setParam(pNamePubKey     , svrPubKey                )
                    
                    clCfgFile.save("./%s.cfg" % clName)
                    if args.qrcode:
                        clCfgFile.saveQRcode("./%s.png" % clName)
                else:
                    print("Cannot find client '%s' - skipping" % clName)

        case "rename":
            clName = args.clname
            newName = args.newname
            clientSection = cfgFile.findClient(clName) if clName else None
            if clientSection:
                clientSection.setParam(pNameClName, newName, True)
                cfgFile.save(configFileName)
            else:
                print("Cannot find client '%s' - ignoring" % clName)

#
# Main code start5s here
#

random.seed()

top_parser = argparse.ArgumentParser()

top_parser.add_argument("-f", "--file", metavar = "CFGFILE", help = "server config filename")

top_subparsers = top_parser.add_subparsers(dest = "obj")
config_parser = top_subparsers.add_parser("config", help = "server config manipulation")
client_parser = top_subparsers.add_parser("client", help = "client config manipulation")

config_subparsers = config_parser.add_subparsers(dest = "cmd")
config_create_parser = config_subparsers.add_parser("create", help = "create server config file")
config_remove_parser = config_subparsers.add_parser("remove", help = "remove server config file")
config_regen_parser  = config_subparsers.add_parser("regen" , help = "regenerate junk parameters")

config_create_parser.add_argument("-i", "--iface"  ,                        help = "interface to use"          )
config_create_parser.add_argument("-p", "--port"   , type = int           , help = "IP port to use"            )
config_create_parser.add_argument("-e", "--extaddr",                        help = "external IP address to use")
config_create_parser.add_argument("-o", "--octet"  , type = int           , help = "IPv4 3rd octet"            )
config_create_parser.add_argument("-6", "--ipv6"   , action = "store_true", help = "Add IPv6 addresses"        )

client_subparsers = client_parser.add_subparsers(dest = "cmd")
client_add_parser      = client_subparsers.add_parser("add"     , help = "add a client"             )
client_remove_parser   = client_subparsers.add_parser("remove"  , help = "remove a client"          )
client_list_parser     = client_subparsers.add_parser("list"    , help = "list existing clients"    )
client_generate_parser = client_subparsers.add_parser("generate", help = "generate client config(s)")
client_rename_parser   = client_subparsers.add_parser("rename"  , help = "rename a client"          )

client_add_parser.add_argument("clname", nargs = "+", help = "client name")

client_remove_parser.add_argument("clname", nargs = "+", help = "client name")

client_list_parser.add_argument("-l", "--long", action = "store_true", help = "show long listing")

client_generate_parser.add_argument("-q", "--qrcode"   , action = "store_true", help = "generate QR codes"               )
client_generate_parser.add_argument("-a", "--all"      , action = "store_true", help = "generate configs for all clients")
client_generate_parser.add_argument("-l", "--local"    , action = "store_true", help = "include local IPs"               )
client_generate_parser.add_argument("-d", "--dns"      , nargs = "+"          , help = "DNS server(s) to use"            )
client_generate_parser.add_argument("-k", "--keepalive", type = int           , help = "keepalive interval"              )
client_generate_parser.add_argument("clname"           , nargs = "*"          , help = "client name(s)"                  )

client_rename_parser.add_argument("clname" , help = "old client name")
client_rename_parser.add_argument("newname", help = "new client name")

args = top_parser.parse_args()

configFileName = defaultConfigFileName
if args.file:
    configFileName = args.file
configBaseName = os.path.basename(configFileName)
tunName = os.path.splitext(configBaseName)[0]

match args.obj:
    case "config":
        handleConfig(args)
    case "client":
        handleClient(args)
    case "_":
        raise RuntimeError("No object specified")
