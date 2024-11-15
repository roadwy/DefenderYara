
rule Trojan_BAT_XenoRAT_PPPH_MTB{
	meta:
		description = "Trojan:BAT/XenoRAT.PPPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 6f ?? 00 00 0a 0c 2b 29 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 2b 11 03 6f ?? 00 00 0a 19 58 04 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}