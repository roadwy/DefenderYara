
rule Trojan_BAT_Redline_AAFO_MTB{
	meta:
		description = "Trojan:BAT/Redline.AAFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 08 16 07 1f 0f 1f 10 1d 2d 61 26 26 26 26 26 26 7e ?? 00 00 04 06 07 1d 2d 58 26 26 26 7e ?? 00 00 04 06 18 28 ?? 00 00 06 7e ?? 00 00 04 06 19 28 ?? 00 00 06 7e ?? 00 00 04 06 28 ?? 00 00 06 0d 7e ?? 00 00 04 09 02 16 02 8e 69 28 ?? 00 00 06 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}