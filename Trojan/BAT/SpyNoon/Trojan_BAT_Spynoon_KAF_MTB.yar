
rule Trojan_BAT_Spynoon_KAF_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 07 11 05 91 11 06 61 11 08 28 90 01 01 00 00 06 13 90 00 } //1
		$a_03_1 = {03 04 59 0a 06 20 00 90 01 01 00 00 58 20 ff 00 00 00 5f 0b 1a 0d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}