
rule Trojan_BAT_XenoRat_AXE_MTB{
	meta:
		description = "Trojan:BAT/XenoRat.AXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 2b 2c 08 6f ?? 00 00 0a 25 72 ?? 02 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 06 09 6f ?? 00 00 0a 2d 07 06 09 6f ?? 00 00 0a 6f ?? 00 00 0a 08 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}