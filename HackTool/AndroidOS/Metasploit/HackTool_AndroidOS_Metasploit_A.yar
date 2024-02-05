
rule HackTool_AndroidOS_Metasploit_A{
	meta:
		description = "HackTool:AndroidOS/Metasploit.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 6d 65 74 61 73 70 6c 6f 69 74 2f 53 63 72 65 65 6e 31 2e 79 61 69 6c } //01 00 
		$a_00_1 = {41 6e 6f 6e 79 6d 6f 75 73 2f 6d 73 2e 73 68 } //01 00 
		$a_00_2 = {2f 6a 6f 6b 65 72 2e 73 68 } //01 00 
		$a_00_3 = {2f 70 61 63 6b 61 67 65 2e 61 70 6b } //00 00 
	condition:
		any of ($a_*)
 
}