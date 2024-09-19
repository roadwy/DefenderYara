
rule HackTool_MacOS_Fscan_A_MTB{
	meta:
		description = "HackTool:MacOS/Fscan.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 68 61 64 6f 77 31 6e 67 2f 66 73 63 61 6e } //1 shadow1ng/fscan
		$a_01_1 = {50 6c 75 67 69 6e 73 2e 4e 65 74 42 69 6f 73 49 6e 66 6f } //1 Plugins.NetBiosInfo
		$a_01_2 = {53 73 68 43 6f 6e 6e 2e 50 61 73 73 77 6f 72 64 2e 66 75 6e 63 33 } //2 SshConn.Password.func3
		$a_01_3 = {68 61 63 6b 67 6f 76 } //1 hackgov
		$a_01_4 = {50 6c 75 67 69 6e 73 2e 53 6d 62 47 68 6f 73 74 53 63 61 6e } //1 Plugins.SmbGhostScan
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}