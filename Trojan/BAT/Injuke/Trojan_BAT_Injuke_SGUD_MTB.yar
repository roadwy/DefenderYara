
rule Trojan_BAT_Injuke_SGUD_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SGUD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 11 05 09 07 08 6f ?? 00 00 0a 17 73 3f 00 00 0a 13 06 11 06 11 04 16 11 04 8e 69 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 28 ?? 00 00 0a 13 07 de 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}