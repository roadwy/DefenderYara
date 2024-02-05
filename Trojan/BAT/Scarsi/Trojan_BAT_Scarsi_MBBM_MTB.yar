
rule Trojan_BAT_Scarsi_MBBM_MTB{
	meta:
		description = "Trojan:BAT/Scarsi.MBBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 2d 00 35 00 41 00 2d 00 39 00 7d 00 40 00 2d 00 7d 00 33 00 40 00 40 00 40 00 2d 00 7d 00 34 00 40 00 40 00 40 00 2d 00 46 00 46 00 2d 00 46 00 46 00 40 00 40 00 2d 00 42 00 38 00 40 00 40 00 40 00 40 00 40 00 40 00 } //01 00 
		$a_81_1 = {53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 } //01 00 
		$a_81_2 = {4b 4b 44 45 57 48 4a 4a 55 44 48 49 53 34 34 } //00 00 
	condition:
		any of ($a_*)
 
}