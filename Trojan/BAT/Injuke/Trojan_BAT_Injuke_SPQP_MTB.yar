
rule Trojan_BAT_Injuke_SPQP_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SPQP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 dc 00 00 70 19 2d 1f 26 28 90 01 03 0a 11 05 6f 90 01 03 0a 0d 08 8e 69 8d 03 00 00 01 13 04 16 0a 2b 1b 0c 2b d9 13 05 2b de 11 04 06 09 06 09 8e 69 5d 91 08 06 91 61 d2 9c 06 17 58 0a 06 08 8e 69 32 e6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}