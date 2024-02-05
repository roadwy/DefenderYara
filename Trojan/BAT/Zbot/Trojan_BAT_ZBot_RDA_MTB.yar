
rule Trojan_BAT_ZBot_RDA_MTB{
	meta:
		description = "Trojan:BAT/ZBot.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {38 61 31 39 32 64 32 36 2d 36 63 30 61 2d 34 62 37 64 2d 62 31 64 63 2d 66 33 30 37 65 66 62 36 30 32 65 38 } //01 00 
		$a_01_1 = {48 69 6a 61 63 6b 20 54 68 69 73 } //01 00 
		$a_01_2 = {38 5a 68 74 32 6c 56 32 68 58 65 64 68 41 69 49 75 53 } //01 00 
		$a_01_3 = {4c 35 38 41 64 5a 65 41 6f } //00 00 
	condition:
		any of ($a_*)
 
}