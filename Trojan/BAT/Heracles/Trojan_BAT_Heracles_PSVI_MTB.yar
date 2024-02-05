
rule Trojan_BAT_Heracles_PSVI_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PSVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {28 41 00 00 0a 13 27 28 90 01 01 00 00 0a 13 28 7e 1e 00 00 04 06 20 44 c3 a4 68 58 07 61 60 80 1e 00 00 04 11 27 73 43 00 00 0a 13 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}