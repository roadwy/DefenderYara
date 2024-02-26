
rule Trojan_BAT_Stealer_MVT_MTB{
	meta:
		description = "Trojan:BAT/Stealer.MVT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {12 11 11 14 28 3d 00 00 06 28 24 00 00 06 00 } //01 00 
		$a_00_1 = {47 6c 75 6b 6f 7a 61 } //00 00  Glukoza
	condition:
		any of ($a_*)
 
}