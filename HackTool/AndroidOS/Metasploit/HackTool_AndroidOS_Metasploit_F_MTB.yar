
rule HackTool_AndroidOS_Metasploit_F_MTB{
	meta:
		description = "HackTool:AndroidOS/Metasploit.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {1a 01 09 01 12 02 23 22 7e 00 6e 30 ae 00 10 02 0c 01 12 00 12 02 6e 30 ce 00 01 02 0c 00 1f 00 0e 00 39 00 14 00 22 00 1e 00 71 00 30 00 00 00 0c 02 70 20 2e 00 20 00 22 02 3f 00 70 20 8b 00 12 00 6e 20 2f 00 20 00 } //1
		$a_01_1 = {1a 01 58 00 62 02 09 00 71 10 c2 00 02 00 0c 02 71 10 c2 00 02 00 0c 03 6e 10 bc 00 03 00 0a 03 d8 03 03 11 22 04 5f 00 70 20 c4 00 34 00 1a 03 b5 00 6e 20 c7 00 34 00 0c 03 6e 20 c7 00 23 00 0c 02 6e 10 c8 00 02 00 0c 02 71 20 39 00 21 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}