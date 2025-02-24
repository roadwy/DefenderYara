
rule HackTool_BAT_FrostyStash_B_dha{
	meta:
		description = "HackTool:BAT/FrostyStash.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 00 65 00 73 00 73 00 61 00 67 00 65 00 44 00 61 00 74 00 61 00 } //1 MessageData
		$a_01_1 = {54 00 79 00 70 00 65 00 44 00 61 00 74 00 61 00 } //1 TypeData
		$a_01_2 = {50 00 61 00 63 00 6b 00 61 00 67 00 65 00 44 00 61 00 74 00 61 00 } //1 PackageData
		$a_01_3 = {53 00 74 00 61 00 74 00 75 00 73 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //1 StatusConnection
		$a_01_4 = {45 00 4e 00 44 00 5f 00 4f 00 46 00 5f 00 4d 00 45 00 53 00 53 00 41 00 47 00 45 00 53 00 } //1 END_OF_MESSAGES
		$a_01_5 = {4e 00 4f 00 5f 00 4d 00 45 00 53 00 53 00 41 00 47 00 45 00 53 00 } //1 NO_MESSAGES
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}