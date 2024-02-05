
rule Ransom_MacOS_EvilQuest_YB_MTB{
	meta:
		description = "Ransom:MacOS/EvilQuest.YB!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 65 2f 74 6f 69 64 69 65 76 69 74 63 65 66 66 65 2f 6c 69 62 74 70 79 72 63 2f 74 70 79 72 63 2e 63 } //01 00 
		$a_00_1 = {45 49 5f 4c 4f 43 4b 46 49 4c 45 5f 44 49 52 } //01 00 
		$a_00_2 = {45 49 5f 43 4f 4e 53 54 5f 52 54 47 5f 47 41 49 4e 45 44 52 4f 4f 54 } //01 00 
		$a_00_3 = {45 49 5f 50 4c 49 53 54 5f 43 4f 4e 54 45 4e 54 53 } //01 00 
		$a_00_4 = {45 49 5f 54 45 4d 50 5f 57 41 53 5f 55 50 44 41 54 45 44 } //00 00 
	condition:
		any of ($a_*)
 
}