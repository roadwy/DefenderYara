
rule HackTool_Linux_Ioxproxy_A_MTB{
	meta:
		description = "HackTool:Linux/Ioxproxy.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 6f 78 2f 6e 65 74 69 6f 2e 46 6f 72 77 61 72 64 55 44 50 } //1 iox/netio.ForwardUDP
		$a_01_1 = {69 6f 78 2f 6f 70 65 72 61 74 65 2e 6c 6f 63 61 6c 32 4c 6f 63 61 6c 55 44 50 } //1 iox/operate.local2LocalUDP
		$a_01_2 = {69 6f 78 2f 6f 70 65 72 61 74 65 2e 72 65 6d 6f 74 65 32 72 65 6d 6f 74 65 54 43 50 } //1 iox/operate.remote2remoteTCP
		$a_01_3 = {69 6f 78 2f 6e 65 74 69 6f 2e 46 6f 72 77 61 72 64 55 6e 63 6f 6e 6e 65 63 74 65 64 55 44 50 } //1 iox/netio.ForwardUnconnectedUDP
		$a_01_4 = {69 6f 78 2f 6f 70 65 72 61 74 65 2e 73 65 72 76 65 72 48 61 6e 64 73 68 61 6b 65 } //1 iox/operate.serverHandshake
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}