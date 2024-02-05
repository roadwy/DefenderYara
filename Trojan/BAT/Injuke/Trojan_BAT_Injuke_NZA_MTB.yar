
rule Trojan_BAT_Injuke_NZA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.NZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 06 08 06 8e 69 5d 91 7e 90 01 03 04 08 91 61 d2 6f 90 01 03 0a 08 17 58 0c 08 7e 90 01 03 04 8e 69 32 dc 90 00 } //01 00 
		$a_01_1 = {21 52 00 76 00 67 00 6e 00 77 00 61 00 6c 00 6e 00 64 00 74 00 79 00 70 00 65 00 63 00 69 00 61 } //01 00 
		$a_01_2 = {39 39 36 62 2d 31 66 30 61 30 36 37 61 61 39 34 37 } //00 00 
	condition:
		any of ($a_*)
 
}