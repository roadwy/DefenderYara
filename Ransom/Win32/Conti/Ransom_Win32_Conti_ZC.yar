
rule Ransom_Win32_Conti_ZC{
	meta:
		description = "Ransom:Win32/Conti.ZC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 01 83 c1 04 89 02 83 c2 04 83 ef 01 75 f1 } //1
		$a_01_1 = {8a 01 8d 49 01 88 44 0a ff 83 ef 01 75 f2 } //1
		$a_01_2 = {8a 01 88 04 0a 41 83 ef 01 75 f5 } //1
		$a_01_3 = {69 0a 95 e9 d1 5b 83 c2 04 69 ff 95 e9 d1 5b 8b c1 c1 e8 18 33 c1 69 c8 95 e9 d1 5b 33 f9 83 eb 01 75 dd } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}