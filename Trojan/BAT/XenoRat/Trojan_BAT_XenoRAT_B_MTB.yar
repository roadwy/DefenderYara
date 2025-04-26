
rule Trojan_BAT_XenoRAT_B_MTB{
	meta:
		description = "Trojan:BAT/XenoRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 28 ?? 00 00 0a 13 05 7e ?? 00 00 0a 11 05 8e 69 20 00 ?? 00 00 1f ?? 28 ?? 00 00 06 13 06 11 05 16 11 06 11 05 8e 69 28 } //4
		$a_03_1 = {0a 16 11 06 7e ?? 00 00 0a 16 7e ?? 00 00 0a 28 ?? 00 00 06 13 07 28 ?? 00 00 0a 13 08 11 08 6f } //2
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2) >=6
 
}