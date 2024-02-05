
rule Trojan_BAT_Seraph_PSNG_MTB{
	meta:
		description = "Trojan:BAT/Seraph.PSNG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {2b 28 7e 0b 00 00 04 20 74 be 66 06 2b 1f 2b 24 2b 29 1d 2c eb 16 2d 10 2b 24 2b 29 2b 2a 2b 2f 2b 34 28 01 00 00 2b 0b de 39 02 2b d5 28 08 00 00 06 2b da 28 38 00 00 06 2b d5 0a 2b d4 28 60 00 00 0a 2b d5 06 2b d4 6f 61 00 00 0a 2b cf 28 62 00 00 0a 2b ca 28 02 00 00 2b 2b c5 } //00 00 
	condition:
		any of ($a_*)
 
}