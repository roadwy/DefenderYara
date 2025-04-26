
rule Ransom_Win32_Conti_ZA{
	meta:
		description = "Ransom:Win32/Conti.ZA,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 04 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {8b 01 83 c1 04 89 02 83 c2 04 83 ee 01 75 f1 } //10
		$a_01_2 = {8a 01 8d 49 01 88 44 0a ff 83 ee 01 75 f2 } //10
		$a_03_3 = {8b c1 c1 e8 18 33 c1 69 f8 95 e9 d1 5b 69 c6 95 e9 d1 5b be 03 00 00 00 33 f8 8b ?? ?? 99 f7 fe 8b ?? ?? 85 d2 74 90 0a 40 00 69 ?? 95 e9 d1 5b c7 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_03_3  & 1)*10) >=31
 
}