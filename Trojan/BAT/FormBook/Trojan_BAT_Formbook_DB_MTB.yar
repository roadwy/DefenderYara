
rule Trojan_BAT_Formbook_DB_MTB{
	meta:
		description = "Trojan:BAT/Formbook.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 41 33 41 43 39 44 44 46 2d 32 30 35 42 2d 34 41 43 30 2d 42 31 42 35 2d 41 42 30 32 32 33 43 33 45 39 39 32 } //01 00 
		$a_81_1 = {67 65 74 5f 53 65 61 47 72 65 65 6e } //01 00 
		$a_81_2 = {53 74 61 66 66 5f 53 61 6c 61 72 79 } //01 00 
		$a_81_3 = {43 6f 6c 6c 6f 71 75 69 75 6d } //01 00 
		$a_81_4 = {67 65 74 46 65 65 73 } //01 00 
		$a_81_5 = {54 6f 79 6f 74 61 } //01 00 
		$a_81_6 = {43 61 6d 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Formbook_DB_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {00 06 07 16 20 90 01 04 6f 90 01 03 0a 0d 09 16 fe 02 13 04 11 04 2c 0c 00 08 07 16 09 6f 90 01 08 16 fe 02 13 05 11 05 2d 90 00 } //01 00 
		$a_80_1 = {47 5a 49 44 45 4b 4b 4b 4b } //GZIDEKKKK  01 00 
		$a_80_2 = {44 45 53 5f 44 65 63 72 79 70 74 } //DES_Decrypt  01 00 
		$a_80_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  01 00 
		$a_80_4 = {54 6f 41 72 72 61 79 } //ToArray  01 00 
		$a_80_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  00 00 
	condition:
		any of ($a_*)
 
}