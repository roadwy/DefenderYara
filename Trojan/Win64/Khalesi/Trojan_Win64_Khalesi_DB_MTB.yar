
rule Trojan_Win64_Khalesi_DB_MTB{
	meta:
		description = "Trojan:Win64/Khalesi.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5a 6d 4a 77 66 51 51 6e 71 41 } //01 00 
		$a_01_1 = {47 65 74 54 65 6d 70 50 61 74 68 41 } //01 00 
		$a_01_2 = {53 77 69 74 63 68 54 6f 46 69 62 65 72 } //01 00 
		$a_01_3 = {43 72 65 61 74 65 46 69 62 65 72 } //01 00 
		$a_01_4 = {43 61 6c 6c 4e 61 6d 65 64 50 69 70 65 41 } //01 00 
		$a_01_5 = {47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}