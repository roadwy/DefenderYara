
rule Trojan_BAT_Kryptik_GINKT_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.GINKT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {24 61 65 37 32 62 36 62 30 2d 65 61 65 36 2d 34 63 30 36 2d 61 32 31 32 2d 65 37 39 65 65 63 63 64 61 38 63 64 } //01 00 
		$a_01_1 = {44 69 73 70 6f 73 65 } //01 00 
		$a_01_2 = {51 5f 49 33 } //01 00 
		$a_01_3 = {00 52 41 57 00 } //00 00 
	condition:
		any of ($a_*)
 
}