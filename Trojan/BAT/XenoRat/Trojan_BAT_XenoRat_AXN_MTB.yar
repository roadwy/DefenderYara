
rule Trojan_BAT_XenoRat_AXN_MTB{
	meta:
		description = "Trojan:BAT/XenoRat.AXN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 2b 41 09 6f ?? 00 00 0a 13 04 00 11 04 72 ?? 02 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 06 11 05 6f ?? 00 00 0a 16 fe 01 13 06 11 06 2c 0b 00 06 11 05 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}