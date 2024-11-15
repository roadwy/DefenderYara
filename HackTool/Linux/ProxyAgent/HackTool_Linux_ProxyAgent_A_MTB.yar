
rule HackTool_Linux_ProxyAgent_A_MTB{
	meta:
		description = "HackTool:Linux/ProxyAgent.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 68 69 64 65 50 72 6f 78 79 50 49 44 } //2 main.hideProxyPID
		$a_01_1 = {6d 61 69 6e 2e 63 68 65 63 6b 50 61 73 73 77 6f 72 64 } //1 main.checkPassword
		$a_01_2 = {6d 61 69 6e 2e 69 73 50 6f 72 74 49 6e 55 73 65 } //1 main.isPortInUse
		$a_01_3 = {6f 70 65 6e 50 6f 72 74 } //1 openPort
		$a_01_4 = {70 72 6f 78 79 46 6f 72 55 52 4c } //1 proxyForURL
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}