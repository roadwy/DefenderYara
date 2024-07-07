
rule Trojan_BAT_Injuke_KAE_MTB{
	meta:
		description = "Trojan:BAT/Injuke.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e1 } //5
		$a_01_1 = {00 11 04 11 05 58 08 11 05 58 47 52 00 11 05 17 58 13 05 11 05 05 fe 04 13 06 11 06 2d e2 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}