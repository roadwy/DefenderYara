
rule Trojan_BAT_RemcosRAT_SYDF_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.SYDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 27 00 00 0a 13 18 00 11 18 17 6f ?? 00 00 0a 00 11 18 18 6f ?? 00 00 0a 00 11 18 20 00 01 00 00 6f ?? 00 00 0a 00 11 18 20 80 00 00 00 6f ?? 00 00 0a 00 11 18 11 08 11 09 6f ?? 00 00 0a 13 19 00 11 19 03 16 03 8e 69 6f ?? 00 00 0a 0b de 38 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}