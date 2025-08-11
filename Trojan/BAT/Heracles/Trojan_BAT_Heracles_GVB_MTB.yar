
rule Trojan_BAT_Heracles_GVB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 28 5a 00 00 0a 02 7b 11 01 00 04 6f 84 04 00 06 2d 22 02 7b 11 01 00 04 28 da 03 00 06 80 f5 00 00 04 02 28 08 03 00 06 02 7b 11 01 00 04 17 6f 85 04 00 06 de 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}