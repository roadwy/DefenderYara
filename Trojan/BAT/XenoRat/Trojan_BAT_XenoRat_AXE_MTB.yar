
rule Trojan_BAT_XenoRat_AXE_MTB{
	meta:
		description = "Trojan:BAT/XenoRat.AXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 18 58 6f ?? 00 00 0a 28 ?? 00 00 06 1e 62 09 60 0d 02 08 19 58 6f ?? 00 00 0a 28 ?? 00 00 06 1f 0c 62 09 60 0d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_XenoRat_AXE_MTB_2{
	meta:
		description = "Trojan:BAT/XenoRat.AXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 2b 2c 08 6f ?? 00 00 0a 25 72 ?? 02 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 06 09 6f ?? 00 00 0a 2d 07 06 09 6f ?? 00 00 0a 6f ?? 00 00 0a 08 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}