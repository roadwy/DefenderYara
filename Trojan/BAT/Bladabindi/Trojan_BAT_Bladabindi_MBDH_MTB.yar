
rule Trojan_BAT_Bladabindi_MBDH_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.MBDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 08 07 08 93 0d 09 20 ff 00 00 00 5f 06 25 17 58 0a 61 1e 62 09 1e 63 06 25 17 58 0a 61 d2 60 d1 9d 08 17 58 0c 08 07 8e 69 fe 04 2d d2 } //01 00 
		$a_01_1 = {36 61 38 61 62 38 31 66 37 62 33 61 } //00 00 
	condition:
		any of ($a_*)
 
}