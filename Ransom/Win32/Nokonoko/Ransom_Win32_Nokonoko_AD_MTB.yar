
rule Ransom_Win32_Nokonoko_AD_MTB{
	meta:
		description = "Ransom:Win32/Nokonoko.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc9 00 ffffffc9 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {8b fa 8b c2 c1 c7 ?? c1 c0 ?? 33 f8 c1 ea ?? 33 fa 8b c6 c1 c8 ?? 8b d6 c1 c2 ?? 33 c2 c1 ee ?? 33 c6 05 ?? ?? ?? ?? 03 c7 03 43 ?? 03 43 ?? 03 c1 41 89 43 ?? 81 f9 ?? ?? ?? ?? 7c ba } //100
		$a_01_2 = {8d 4d a8 03 ca 42 8a 04 19 32 01 88 04 31 3b d7 72 ee } //100
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100+(#a_01_2  & 1)*100) >=201
 
}