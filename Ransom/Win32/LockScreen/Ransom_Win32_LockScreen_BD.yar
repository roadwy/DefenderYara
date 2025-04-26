
rule Ransom_Win32_LockScreen_BD{
	meta:
		description = "Ransom:Win32/LockScreen.BD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {89 03 ba 01 00 00 80 8b 03 e8 ?? ?? ?? ?? b1 01 } //1
		$a_03_1 = {8b c3 8b d4 b9 01 04 00 00 e8 ?? ?? ?? ?? 81 c4 04 04 00 00 5b c3 } //1
		$a_03_2 = {40 65 63 68 6f 20 6f 66 66 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 54 69 74 6c 65 } //1
		$a_01_3 = {c4 e8 f1 ef e5 f2 f7 e5 f0 20 e7 e0 e4 e0 f7 20 57 69 6e 64 6f 77 73 00 } //1
		$a_01_4 = {74 61 73 6b 6d 67 72 2e 65 78 65 00 6f 70 65 6e 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}