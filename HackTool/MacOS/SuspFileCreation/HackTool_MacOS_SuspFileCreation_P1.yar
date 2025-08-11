
rule HackTool_MacOS_SuspFileCreation_P1{
	meta:
		description = "HackTool:MacOS/SuspFileCreation.P1,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 00 68 00 6d 00 6f 00 64 00 20 00 } //5 chmod 
		$a_00_1 = {2b 00 73 00 } //5 +s
		$a_00_2 = {34 00 37 00 37 00 37 00 } //5 4777
		$a_00_3 = {34 00 37 00 35 00 35 00 } //5 4755
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5) >=10
 
}