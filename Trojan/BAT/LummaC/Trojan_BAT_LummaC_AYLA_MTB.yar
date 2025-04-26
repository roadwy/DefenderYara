
rule Trojan_BAT_LummaC_AYLA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AYLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 9a 28 ?? 00 00 0a 03 08 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 0d 09 59 08 1f 0c 5d 59 20 00 01 00 00 58 20 00 01 00 00 5d d1 13 04 07 11 04 6f ?? 00 00 0a 26 08 17 58 0c 08 06 8e 69 32 c0 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}