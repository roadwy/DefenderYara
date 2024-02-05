
rule Trojan_AndroidOS_Spitmo_A{
	meta:
		description = "Trojan:AndroidOS/Spitmo.A,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 72 65 63 65 69 76 65 72 3d 00 } //01 00 
		$a_01_1 = {26 74 65 78 74 3d 00 } //01 00 
		$a_01_2 = {32 35 31 33 34 30 00 } //01 00 
		$a_01_3 = {33 32 35 30 30 30 00 } //01 00 
		$a_01_4 = {3c 69 6e 69 74 3e 00 } //01 00 
		$a_01_5 = {3f 73 65 6e 64 65 72 3d 00 } //01 00 
		$a_01_6 = {50 41 53 53 57 4f 52 44 5f 4e 55 4d 42 45 52 00 } //01 00 
		$a_01_7 = {50 48 4f 4e 45 5f 4e 55 4d 42 45 52 00 } //00 00 
	condition:
		any of ($a_*)
 
}