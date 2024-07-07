
rule Ransom_Win32_Conti_ZG{
	meta:
		description = "Ransom:Win32/Conti.ZG,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc9 00 ffffffc9 00 05 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {8d 04 5b c7 } //50
		$a_01_2 = {8d 34 c5 95 e9 d1 5b } //50
		$a_03_3 = {75 15 0f b6 4a 02 c1 e1 10 90 0a 1a 00 33 c9 90 02 01 83 90 01 01 01 74 1a 83 90 01 01 01 74 0c 83 90 01 01 01 90 00 } //50
		$a_01_4 = {0f b6 42 01 c1 e0 08 33 c8 0f b6 02 33 c8 } //50
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*50+(#a_01_2  & 1)*50+(#a_03_3  & 1)*50+(#a_01_4  & 1)*50) >=201
 
}