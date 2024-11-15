
rule HackTool_MacOS_Fscan_B_MTB{
	meta:
		description = "HackTool:MacOS/Fscan.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 63 67 69 53 63 61 6e } //5 FcgiScan
		$a_01_1 = {50 6c 75 67 69 6e 73 2e 50 6f 72 74 53 63 61 6e } //5 Plugins.PortScan
		$a_01_2 = {53 6d 62 47 68 6f 73 74 53 63 61 6e } //5 SmbGhostScan
		$a_01_3 = {50 6c 75 67 69 6e 73 2e 6d 61 6b 65 53 4d 42 31 54 72 61 6e 73 32 45 78 70 6c 6f 69 74 50 61 63 6b 65 74 } //1 Plugins.makeSMB1Trans2ExploitPacket
		$a_01_4 = {47 65 74 49 73 44 6f 6d 61 69 6e 4e 61 6d 65 53 65 72 76 65 72 } //1 GetIsDomainNameServer
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=16
 
}