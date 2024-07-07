
rule Ransom_Win32_Nymaim_D{
	meta:
		description = "Ransom:Win32/Nymaim.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 b9 10 27 00 00 f7 e1 8d 4d f8 f7 d8 83 d2 00 f7 da 89 01 89 51 04 51 6a 00 e8 } //1
		$a_03_1 = {89 47 01 c6 47 05 c3 ff 75 90 01 01 90 03 01 01 56 57 68 90 01 04 68 90 01 04 e8 90 0a 40 00 c6 07 68 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}