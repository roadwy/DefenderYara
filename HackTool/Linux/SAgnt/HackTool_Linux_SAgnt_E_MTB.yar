
rule HackTool_Linux_SAgnt_E_MTB{
	meta:
		description = "HackTool:Linux/SAgnt.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 28 2a 63 6f 6e 6e 50 6f 6f 6c 29 2e 61 64 64 43 6f 6e 6e } //1 main.(*connPool).addConn
		$a_01_1 = {6d 61 69 6e 2e 6e 65 77 41 6e 74 69 74 72 61 63 6b 4c 69 6e 6b 54 61 73 6b } //1 main.newAntitrackLinkTask
		$a_01_2 = {6d 61 69 6e 2e 28 2a 61 6e 74 69 74 72 61 63 6b 4c 69 6e 6b 4e 65 74 29 2e 61 64 64 54 61 73 6b 43 6f 6e 6e } //1 main.(*antitrackLinkNet).addTaskConn
		$a_01_3 = {6d 61 69 6e 2e 67 65 74 49 50 76 34 43 6c 69 65 6e 74 } //1 main.getIPv4Client
		$a_01_4 = {6d 61 69 6e 2e 72 75 6e 41 6e 74 69 74 72 61 63 6b 52 6f 75 74 65 72 } //1 main.runAntitrackRouter
		$a_01_5 = {6d 61 69 6e 2e 28 2a 73 65 72 76 65 72 4d 73 67 44 69 73 70 61 74 63 68 29 2e 73 74 61 72 74 } //1 main.(*serverMsgDispatch).start
		$a_01_6 = {6d 61 69 6e 2e 61 6c 6c 6f 77 54 75 6e 46 6f 72 77 61 72 64 } //1 main.allowTunForward
		$a_01_7 = {6d 61 69 6e 2e 61 64 64 53 6e 61 74 52 75 6c 65 } //1 main.addSnatRule
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=6
 
}