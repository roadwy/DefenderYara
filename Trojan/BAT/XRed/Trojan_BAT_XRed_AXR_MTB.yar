
rule Trojan_BAT_XRed_AXR_MTB{
	meta:
		description = "Trojan:BAT/XRed.AXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 72 ?? 00 00 70 6f ?? 00 00 0a 2d 0e 11 04 72 ?? 00 00 70 28 ?? 00 00 0a 13 04 11 04 09 20 10 27 00 00 6f ?? 00 00 0a 13 08 12 08 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 13 04 02 03 11 04 28 ?? 00 00 06 28 ?? 00 00 0a 13 05 11 05 72 ?? 00 00 70 6f ?? 00 00 0a 2d 0e 11 05 72 ?? 00 00 70 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}