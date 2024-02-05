
rule HackTool_AndroidOS_Mesploit_C{
	meta:
		description = "HackTool:AndroidOS/Mesploit.C,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 63 70 3a 2f 2f 38 37 2e 31 39 2e 37 33 2e 38 3a 32 34 30 37 39 } //01 00 
		$a_03_1 = {2e 64 65 78 00 0e 2e 90 02 20 00 04 2e 6a 61 72 00 90 00 } //01 00 
		$a_01_2 = {63 72 65 61 74 65 4e 65 77 46 69 6c 65 } //01 00 
		$a_01_3 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}