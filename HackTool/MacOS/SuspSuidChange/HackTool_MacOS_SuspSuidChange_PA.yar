
rule HackTool_MacOS_SuspSuidChange_PA{
	meta:
		description = "HackTool:MacOS/SuspSuidChange.PA,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 74 00 6f 00 75 00 63 00 68 00 20 00 2f 00 74 00 6d 00 70 00 2f 00 73 00 62 00 2d 00 [0-60] 20 00 63 00 68 00 6d 00 6f 00 64 00 20 00 75 00 2b 00 73 00 20 00 2f 00 74 00 6d 00 70 00 2f 00 73 00 62 00 2d 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}