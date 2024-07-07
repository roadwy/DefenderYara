
rule Ransom_Win32_Tobfy_R{
	meta:
		description = "Ransom:Win32/Tobfy.R,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 06 00 00 "
		
	strings :
		$a_00_0 = {ab 37 f4 63 16 f1 92 72 2c ae 80 1d 3b 1f 04 50 5e 61 f3 } //10
		$a_01_1 = {e3 40 fe 45 fd 0f b6 45 fd 0f b6 14 38 88 55 ff 00 55 fc 0f b6 45 fc 8a 14 38 88 55 fe 0f b6 45 fd 88 14 38 0f b6 45 fc 8a 55 ff 88 14 38 8a 55 ff 02 55 fe 8a 14 3a 8b 45 f8 30 14 30 ff 45 f8 e2 c0 8a 45 fd 88 03 8a 45 fc 88 43 01 } //1
		$a_03_2 = {3d c9 00 00 00 75 0f 68 a7 a7 a7 00 ff 75 10 e8 90 01 02 00 00 eb 90 01 01 3d ca 00 00 00 75 90 01 01 6a 00 ff 75 10 e8 90 00 } //1
		$a_01_3 = {d7 84 c0 78 f7 8a e0 c0 e8 04 c0 e4 04 0b d0 49 78 28 ac d7 84 c0 78 f7 8a e0 c0 e8 02 c0 e4 06 c1 e0 08 0b d0 49 78 12 ac d7 84 c0 78 f7 c1 e0 10 0b d0 89 17 } //1
		$a_01_4 = {4d 00 6f 00 6e 00 65 00 79 00 50 00 61 00 6b 00 } //10 MoneyPak
		$a_01_5 = {23 33 32 37 37 30 00 41 32 41 5f 30 33 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10) >=31
 
}