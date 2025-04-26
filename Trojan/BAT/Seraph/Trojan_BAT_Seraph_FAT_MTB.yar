
rule Trojan_BAT_Seraph_FAT_MTB{
	meta:
		description = "Trojan:BAT/Seraph.FAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 26 16 25 2d 0a 2d 07 1e 2c 0a de 3b 2b 14 19 25 2c f0 2c e3 2b eb 2b 11 2b df 2b 14 2b dd 2b 17 2b db 2b 1a 16 2d e0 2b e5 28 ?? 00 00 06 2b e8 28 ?? 00 00 2b 2b e5 28 ?? 00 00 2b 2b e2 0a 2b e3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}