
rule Trojan_BAT_Seraph_AATS_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AATS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 08 06 08 91 7e 90 01 01 00 00 04 7e 90 01 01 00 00 04 20 f8 be 66 06 28 90 01 01 02 00 06 28 90 01 01 03 00 06 59 d2 9c 08 17 58 16 2c 15 26 08 06 8e 69 16 2d f4 32 cf 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}