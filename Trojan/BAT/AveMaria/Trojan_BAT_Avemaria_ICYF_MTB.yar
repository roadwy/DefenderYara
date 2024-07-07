
rule Trojan_BAT_Avemaria_ICYF_MTB{
	meta:
		description = "Trojan:BAT/Avemaria.ICYF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 08 a1 00 70 17 8d 17 00 00 01 25 16 07 a2 25 0c 14 14 17 8d 73 00 00 01 25 16 17 9c 25 } //1
		$a_01_1 = {42 00 75 00 6e 00 69 00 35 00 35 00 35 00 66 00 75 00 5f 00 54 00 65 00 35 00 35 00 35 00 35 00 78 00 74 00 42 00 35 00 35 00 35 00 6f 00 78 00 } //1 Buni555fu_Te5555xtB555ox
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_3 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_01_4 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}