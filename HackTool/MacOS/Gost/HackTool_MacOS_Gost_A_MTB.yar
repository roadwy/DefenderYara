
rule HackTool_MacOS_Gost_A_MTB{
	meta:
		description = "HackTool:MacOS/Gost.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 6f 73 74 2e 68 74 74 70 32 43 6f 6e 6e } //1 gost.http2Conn
		$a_01_1 = {67 6f 73 74 2e 68 32 54 72 61 6e 73 70 6f 72 74 65 72 } //1 gost.h2Transporter
		$a_01_2 = {6d 61 69 6e 2e 70 61 72 73 65 42 79 70 61 73 73 } //1 main.parseBypass
		$a_01_3 = {67 6f 73 74 2e 42 79 70 61 73 73 } //1 gost.Bypass
		$a_01_4 = {67 6f 73 74 2e 73 73 68 52 65 6d 6f 74 65 46 6f 72 77 61 72 64 43 6f 6e 6e 65 63 74 6f 72 } //1 gost.sshRemoteForwardConnector
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}