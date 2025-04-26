
rule HackTool_MacOS_Masscan_A_MTB{
	meta:
		description = "HackTool:MacOS/Masscan.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 73 73 63 61 6e 20 2d 2d 6e 6d 61 70 } //1 masscan --nmap
		$a_01_1 = {6d 61 73 73 69 70 2d 72 61 6e 67 65 73 76 34 2e 63 } //1 massip-rangesv4.c
		$a_01_2 = {6d 61 73 73 63 61 6e 2d 74 65 73 74 } //1 masscan-test
		$a_01_3 = {75 6e 69 63 6f 72 6e 73 63 61 6e } //1 unicornscan
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}