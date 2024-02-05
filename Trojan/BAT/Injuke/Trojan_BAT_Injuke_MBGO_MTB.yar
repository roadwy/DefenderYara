
rule Trojan_BAT_Injuke_MBGO_MTB{
	meta:
		description = "Trojan:BAT/Injuke.MBGO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 06 11 05 11 20 9a 1f 10 28 90 01 01 00 00 0a b4 6f 90 01 01 00 00 0a 00 11 20 17 d6 13 20 11 20 11 1f 31 df 90 00 } //01 00 
		$a_01_1 = {51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 00 11 47 00 69 00 61 00 79 00 2e 00 43 00 43 00 4d } //01 00 
		$a_01_2 = {32 31 37 65 30 38 61 33 } //00 00 
	condition:
		any of ($a_*)
 
}