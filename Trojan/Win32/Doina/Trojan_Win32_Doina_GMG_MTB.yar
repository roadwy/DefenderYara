
rule Trojan_Win32_Doina_GMG_MTB{
	meta:
		description = "Trojan:Win32/Doina.GMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b6 da 80 c3 98 80 75 0c 20 8d 64 24 04 66 0f b6 d8 } //10
		$a_01_1 = {fe c6 80 e2 0b 8a 06 d2 f2 d0 c2 28 d8 3c c4 } //10
		$a_01_2 = {47 6d 58 4f 6a 6b 4a 4a } //1 GmXOjkJJ
		$a_01_3 = {50 2e 76 6d 70 30 } //1 P.vmp0
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=22
 
}