
rule HackTool_AndroidOS_Metasploit_C_MTB{
	meta:
		description = "HackTool:AndroidOS/Metasploit.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 30 00 01 38 00 13 00 07 30 1f 00 00 01 12 01 72 10 ec 1d 03 00 0a 03 1c 02 0e 01 72 40 40 04 10 23 0c 03 1f 03 b4 09 11 03 12 03 11 03 00 00 03 00 } //1
		$a_01_1 = {54 20 0c 00 6e 10 09 07 00 00 0c 00 6e 20 78 03 30 00 0c 00 39 00 10 00 22 00 c4 06 70 10 53 1f 00 00 54 21 0c 00 6e 10 09 07 01 00 0c 01 6e 30 88 03 31 00 11 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}