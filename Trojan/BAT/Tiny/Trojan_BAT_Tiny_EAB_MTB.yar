
rule Trojan_BAT_Tiny_EAB_MTB{
	meta:
		description = "Trojan:BAT/Tiny.EAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 08 06 28 10 00 00 06 00 08 06 28 11 00 00 06 00 08 06 28 12 00 00 06 00 00 08 17 58 0c 08 20 e8 03 00 00 fe 04 0d 09 2d d6 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}