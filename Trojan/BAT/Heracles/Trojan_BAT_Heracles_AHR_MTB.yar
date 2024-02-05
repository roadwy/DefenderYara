
rule Trojan_BAT_Heracles_AHR_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 1f 64 20 d0 07 00 00 6f 19 00 00 0a 28 1a 00 00 0a 25 6f 1f 00 00 0a 72 90 01 01 00 00 70 6f 22 00 00 0a 25 6f 1f 00 00 0a 17 6f 23 00 00 0a 06 1f 64 20 d0 07 00 00 6f 19 00 00 0a 28 1a 00 00 0a 6f 24 00 00 0a 26 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}