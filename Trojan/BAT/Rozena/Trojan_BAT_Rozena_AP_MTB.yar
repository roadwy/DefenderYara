
rule Trojan_BAT_Rozena_AP_MTB{
	meta:
		description = "Trojan:BAT/Rozena.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 13 06 16 13 17 2b 4d 16 13 18 2b 3c 08 11 18 11 17 6f 90 01 03 0a 13 19 7e 04 00 00 04 11 19 12 1a 6f 90 01 03 0a 2c 0e 11 05 11 06 25 17 58 13 06 11 1a 9d 2b 0c 11 05 11 06 25 17 58 13 06 1f 30 9d 11 18 17 58 13 18 11 18 11 04 32 be 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}