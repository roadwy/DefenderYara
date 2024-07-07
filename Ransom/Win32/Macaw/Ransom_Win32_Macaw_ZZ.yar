
rule Ransom_Win32_Macaw_ZZ{
	meta:
		description = "Ransom:Win32/Macaw.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {8b 4c 24 04 56 8b f0 c1 e8 02 83 e6 03 85 c0 74 0f 57 8b 3a 89 39 83 c1 04 83 c2 04 48 75 f3 5f 85 f6 74 0d 8b c1 2b d1 8a 0c 02 88 08 40 4e 75 f7 8b 44 24 08 5e c2 04 00 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*100) >=101
 
}