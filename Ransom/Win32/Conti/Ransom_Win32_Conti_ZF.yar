
rule Ransom_Win32_Conti_ZF{
	meta:
		description = "Ransom:Win32/Conti.ZF,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 04 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {8d 45 f8 50 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 83 c4 04 } //10
		$a_03_2 = {68 00 10 00 00 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 83 c4 04 } //10
		$a_03_3 = {8b 0e 03 ca 33 d2 38 11 74 0d 66 0f 1f 44 00 00 42 80 3c 0a 00 75 f9 51 e8 ?? ?? ?? ?? 83 c4 04 3b 45 f4 74 24 8b 45 fc 47 8b 55 f8 83 c6 04 83 c3 02 3b 78 18 72 c9 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10+(#a_03_3  & 1)*10) >=31
 
}