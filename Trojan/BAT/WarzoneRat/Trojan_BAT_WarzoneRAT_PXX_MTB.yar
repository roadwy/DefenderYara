
rule Trojan_BAT_WarzoneRAT_PXX_MTB{
	meta:
		description = "Trojan:BAT/WarzoneRAT.PXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 06 8e 69 18 5b 11 05 58 91 06 11 05 91 61 d2 13 06 11 04 11 05 11 06 9c 00 11 05 17 58 13 05 11 05 11 04 8e 69 fe 04 13 07 11 07 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}