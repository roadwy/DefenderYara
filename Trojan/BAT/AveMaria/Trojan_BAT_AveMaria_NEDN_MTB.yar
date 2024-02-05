
rule Trojan_BAT_AveMaria_NEDN_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f 90 01 01 00 00 0a 11 04 17 25 2c 07 58 13 04 11 04 07 8e 69 16 2d fc 32 d9 1a 2c af 09 6f 90 01 01 00 00 0a 13 05 90 00 } //05 00 
		$a_01_1 = {50 6f 77 65 72 65 64 20 62 79 20 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 20 38 2e 31 2e 32 2e 34 39 37 35 } //00 00 
	condition:
		any of ($a_*)
 
}