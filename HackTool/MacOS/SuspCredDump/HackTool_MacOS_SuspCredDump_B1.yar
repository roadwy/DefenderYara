
rule HackTool_MacOS_SuspCredDump_B1{
	meta:
		description = "HackTool:MacOS/SuspCredDump.B1,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {64 00 73 00 63 00 6c 00 20 00 2e 00 20 00 72 00 65 00 61 00 64 00 [0-80] 64 00 73 00 41 00 74 00 74 00 72 00 54 00 79 00 70 00 65 00 4e 00 61 00 74 00 69 00 76 00 65 00 3a 00 53 00 68 00 61 00 64 00 6f 00 77 00 48 00 61 00 73 00 68 00 44 00 61 00 74 00 61 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}