
rule Trojan_BAT_PowDow_NEAA_MTB{
	meta:
		description = "Trojan:BAT/PowDow.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0d 09 06 6f 27 00 00 0a 00 09 18 6f 28 00 00 0a 00 09 18 6f 29 00 00 0a 00 09 6f 2a 00 00 0a 13 04 11 04 07 16 07 8e 69 6f 2b 00 00 0a 13 05 09 } //05 00 
		$a_01_1 = {48 69 64 65 2d 50 6f 77 65 72 53 68 65 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}