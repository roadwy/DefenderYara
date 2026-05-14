
rule Trojan_BAT_Remcos_ABSB_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 0a 11 00 11 06 11 00 91 11 0b 61 d2 9c 20 } //5
		$a_01_1 = {11 01 11 01 11 04 94 11 01 11 02 94 58 20 00 01 00 00 5d 94 13 0b } //2
		$a_01_2 = {11 02 11 01 11 00 94 58 11 09 11 00 94 58 20 00 01 00 00 5d 13 02 } //2
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=9
 
}