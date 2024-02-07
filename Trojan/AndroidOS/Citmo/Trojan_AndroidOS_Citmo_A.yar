
rule Trojan_AndroidOS_Citmo_A{
	meta:
		description = "Trojan:AndroidOS/Citmo.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 6d 73 62 6c 6f 63 6b 65 72 } //01 00  smsblocker
		$a_01_1 = {41 75 74 68 20 52 65 71 75 65 73 74 20 74 6f 3a } //01 00  Auth Request to:
		$a_01_2 = {68 69 64 65 20 53 4d 53 } //01 00  hide SMS
		$a_01_3 = {6d 2f 61 73 32 32 35 6b 65 72 74 6f } //01 00  m/as225kerto
		$a_01_4 = {61 63 74 69 76 69 74 79 5f 63 6f 64 65 } //00 00  activity_code
	condition:
		any of ($a_*)
 
}