
rule HackTool_MacOS_SuspCredDump_A1{
	meta:
		description = "HackTool:MacOS/SuspCredDump.A1,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {6c 00 61 00 7a 00 61 00 67 00 6e 00 65 00 [0-80] 2f 00 74 00 6d 00 70 00 2f 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}