
rule Trojan_BAT_AveMariaRAT_M_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {03 20 00 01 00 00 5d 17 5b d2 } //2
		$a_01_1 = {03 8e 69 17 5b } //2
		$a_01_2 = {03 04 17 58 06 5d 91 } //2
		$a_01_3 = {03 04 61 05 59 20 00 01 00 00 58 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}