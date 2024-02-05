
rule Trojan_BAT_DarkTortilla_RDB_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {35 38 36 37 30 61 39 61 2d 62 65 30 37 2d 34 39 36 33 2d 62 34 61 36 2d 39 61 62 30 34 34 35 39 64 36 38 66 } //01 00 
		$a_01_1 = {72 38 4e 48 62 34 37 43 74 6d 30 51 39 46 65 79 35 57 54 6f 32 61 33 59 36 5a 69 70 31 } //01 00 
		$a_01_2 = {64 39 53 31 58 6b } //01 00 
		$a_01_3 = {6e 32 50 36 54 67 } //00 00 
	condition:
		any of ($a_*)
 
}