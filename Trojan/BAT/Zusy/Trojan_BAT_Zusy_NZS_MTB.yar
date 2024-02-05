
rule Trojan_BAT_Zusy_NZS_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 1e 17 d6 13 1e 11 09 6f 90 01 03 0a 13 0a 11 1e 1b 3e 90 01 03 00 11 0b 2c 3e 11 0a 72 90 01 03 70 6f 90 01 03 0a 2c 1b 16 13 0b 11 0a 72 90 01 03 70 72 90 01 03 70 6f 90 01 03 0a 13 17 38 90 01 03 00 90 00 } //01 00 
		$a_01_1 = {4d 38 59 20 44 61 74 61 20 4d 61 69 6c 20 32 20 43 53 56 } //00 00 
	condition:
		any of ($a_*)
 
}