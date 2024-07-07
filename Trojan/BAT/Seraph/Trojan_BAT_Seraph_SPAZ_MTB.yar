
rule Trojan_BAT_Seraph_SPAZ_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 1b 16 2c 1f 26 7e 90 01 03 04 2b 1a 16 2b 1a 8e 69 2b 19 17 2c 04 2b 1b 2b 1c de 20 28 90 01 03 06 2b de 0a 2b df 06 2b e3 06 2b e3 28 90 01 03 06 2b e0 06 2b e2 0b 2b e1 26 de c2 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}