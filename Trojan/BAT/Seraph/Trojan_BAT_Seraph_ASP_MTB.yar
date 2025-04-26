
rule Trojan_BAT_Seraph_ASP_MTB{
	meta:
		description = "Trojan:BAT/Seraph.ASP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 15 2d 03 26 2b 3f 0a 2b fb 00 28 16 00 00 06 17 2d 26 26 28 0b 00 00 0a 07 6f 0c 00 00 0a 72 4b 00 00 70 7e 0d 00 00 0a 6f 0e 00 00 0a 28 0f 00 00 0a 16 2c 06 26 de 13 0b 2b d8 0c 2b f8 26 de 00 06 17 58 0a 06 1b 32 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}