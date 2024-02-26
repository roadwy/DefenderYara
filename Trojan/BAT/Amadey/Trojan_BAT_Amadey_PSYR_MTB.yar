
rule Trojan_BAT_Amadey_PSYR_MTB{
	meta:
		description = "Trojan:BAT/Amadey.PSYR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {6f 17 00 00 06 6f 27 00 00 0a 6f 28 00 00 0a 6f 29 00 00 0a 0a 72 35 00 00 70 06 28 90 01 01 00 00 0a 72 43 00 00 70 72 47 00 00 70 6f 2b 00 00 0a 28 2c 00 00 0a 16 14 28 90 01 01 00 00 0a 26 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}