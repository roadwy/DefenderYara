
rule Trojan_BAT_Tedy_SPH_MTB{
	meta:
		description = "Trojan:BAT/Tedy.SPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 76 6e 54 63 70 6e 4e 65 74 2e 6c 69 62 } //01 00  SvnTcpnNet.lib
		$a_01_1 = {53 76 6e 54 63 70 6e 4e 65 74 2e 6a 73 6f 6e 4d 6f 64 65 6c 73 2e 53 53 48 } //01 00  SvnTcpnNet.jsonModels.SSH
		$a_01_2 = {53 76 6e 54 63 70 6e 4e 65 74 2e 6a 73 6f 6e 4d 6f 64 65 6c 73 2e 46 54 50 } //01 00  SvnTcpnNet.jsonModels.FTP
		$a_01_3 = {53 76 6e 54 63 70 6e 4e 65 74 2e 6a 73 6f 6e 4d 6f 64 65 6c 73 2e 53 63 72 65 65 6e 73 68 6f 74 } //00 00  SvnTcpnNet.jsonModels.Screenshot
	condition:
		any of ($a_*)
 
}