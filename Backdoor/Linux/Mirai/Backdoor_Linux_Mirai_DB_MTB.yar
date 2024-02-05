
rule Backdoor_Linux_Mirai_DB_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 74 74 61 63 6b 5f 76 65 63 74 6f 72 5f 75 64 70 } //01 00 
		$a_01_1 = {6b 69 6c 6c 65 72 5f 70 69 64 } //01 00 
		$a_01_2 = {6b 69 6c 6c 65 72 5f 6b 69 6c 6c 5f 62 79 5f 70 6f 72 74 } //01 00 
		$a_01_3 = {61 74 74 61 63 6b 5f 6b 69 6c 6c 5f 61 6c 6c } //01 00 
		$a_01_4 = {6b 69 6c 6c 65 72 5f 72 65 61 6c 70 61 74 68 } //01 00 
		$a_01_5 = {61 74 74 61 63 6b 5f 6f 6e 67 6f 69 6e 67 } //01 00 
		$a_01_6 = {69 6e 69 74 5f 6b 69 6c 6c 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}