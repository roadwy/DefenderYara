
rule Trojan_BAT_LummaC_AXGA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AXGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 02 06 91 66 d2 9c 02 06 8f ?? 00 00 01 25 47 1f 69 59 d2 52 02 06 8f ?? 00 00 01 25 47 1f 34 58 d2 52 00 06 17 58 0a 06 02 8e 69 fe 04 0b 07 2d cc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}