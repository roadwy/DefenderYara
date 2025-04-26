
rule Trojan_BAT_Mamut_KAD_MTB{
	meta:
		description = "Trojan:BAT/Mamut.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 06 02 07 91 6f ?? 00 00 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08 2d e8 } //5
		$a_03_1 = {00 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05 07 11 04 16 11 05 6f ?? 00 00 0a 00 00 11 05 16 fe 02 13 06 11 06 2d d8 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}