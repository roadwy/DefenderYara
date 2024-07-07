
rule Trojan_BAT_Heracles_PSKJ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PSKJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 8b 00 00 70 28 4a 00 00 06 1d 2d 1c 26 28 90 01 03 0a 06 6f 90 01 03 0a 28 90 01 03 0a 28 49 00 00 06 1c 2d 06 26 de 09 0a 2b e2 0b 2b f8 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}