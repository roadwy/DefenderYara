
rule Trojan_BAT_LummaC_AMF_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 02 06 02 06 91 66 d2 9c 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 58 d2 81 ?? 00 00 01 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 59 d2 81 ?? 00 00 01 00 06 17 58 0a 06 02 8e 69 fe 04 0b 07 2d bc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}