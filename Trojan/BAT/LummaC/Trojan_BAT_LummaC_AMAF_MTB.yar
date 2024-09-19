
rule Trojan_BAT_LummaC_AMAF_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AMAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 66 d2 9c 02 11 ?? 8f ?? 00 00 01 25 71 ?? 00 00 01 20 ?? ?? ?? ?? 58 d2 81 ?? 00 00 01 02 11 ?? 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 59 d2 81 ?? 00 00 01 00 11 ?? 17 58 13 ?? 11 ?? 02 8e 69 fe } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}