
rule Trojan_BAT_ZgRAT_KAA_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 08 06 09 91 9c 08 17 58 0c 09 17 59 0d 09 16 2f ee } //5
		$a_01_1 = {4b 66 65 69 6f 66 } //1 Kfeiof
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_ZgRAT_KAA_MTB_2{
	meta:
		description = "Trojan:BAT/ZgRAT.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 08 09 06 09 91 7e ?? 00 00 04 59 d2 9c 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d e1 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}