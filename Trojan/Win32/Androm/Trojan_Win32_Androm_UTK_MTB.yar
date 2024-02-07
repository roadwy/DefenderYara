
rule Trojan_Win32_Androm_UTK_MTB{
	meta:
		description = "Trojan:Win32/Androm.UTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 70 6f 63 61 74 61 73 74 61 73 69 73 } //01 00  Apocatastasis
		$a_81_1 = {4d 61 73 6b 69 6e 73 6b 72 69 76 6e 69 6e 67 } //01 00  Maskinskrivning
		$a_81_2 = {49 64 65 6e 74 69 74 65 74 73 6d 72 6b 65 72 6e 65 73 } //01 00  Identitetsmrkernes
		$a_81_3 = {53 74 72 65 6e 67 74 68 66 75 6c 6e 65 73 73 36 } //01 00  Strengthfulness6
		$a_81_4 = {55 6e 63 6f 6e 63 65 70 74 75 61 6c 69 7a 65 64 33 } //01 00  Unconceptualized3
		$a_81_5 = {42 45 5a 50 4f 50 4f 56 45 54 53 } //01 00  BEZPOPOVETS
		$a_81_6 = {48 4f 56 45 44 47 41 44 45 4e } //01 00  HOVEDGADEN
		$a_81_7 = {53 4c 55 54 41 4b 54 45 52 } //01 00  SLUTAKTER
		$a_81_8 = {42 61 63 6b 66 69 73 63 68 65 36 } //01 00  Backfische6
		$a_81_9 = {66 72 65 6d 6d 65 64 62 67 65 72 73 } //00 00  fremmedbgers
	condition:
		any of ($a_*)
 
}