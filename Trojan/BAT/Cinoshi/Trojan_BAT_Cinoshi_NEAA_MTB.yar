
rule Trojan_BAT_Cinoshi_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Cinoshi.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {35 66 32 63 35 37 62 32 2d 61 64 31 30 2d 34 36 64 38 2d 39 30 30 32 2d 34 61 30 65 39 61 37 64 66 65 31 34 } //02 00 
		$a_01_1 = {4a 6f 68 6e 79 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}