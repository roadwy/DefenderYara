
rule Trojan_BAT_RiseProStealer_AAOF_MTB{
	meta:
		description = "Trojan:BAT/RiseProStealer.AAOF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 33 36 34 38 64 38 39 2d 62 30 30 63 2d 34 37 65 66 2d 39 31 30 30 2d 31 63 35 35 35 37 37 36 38 63 33 61 } //01 00 
		$a_01_1 = {50 00 6f 00 6c 00 79 00 6d 00 6f 00 64 00 58 00 54 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_2 = {52 65 76 65 72 73 65 } //01 00 
		$a_01_3 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}