
rule Worm_Win32_Yeltminky_A_dll{
	meta:
		description = "Worm:Win32/Yeltminky.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 10 66 90 01 04 88 1c 11 42 4e 75 ef 90 00 } //1
		$a_01_1 = {44 72 76 4b 69 6c 6c 65 72 } //1 DrvKiller
		$a_01_2 = {66 ba 30 08 66 b8 22 00 e8 } //1
		$a_01_3 = {68 48 20 22 00 53 ff d6 53 ff d7 68 d0 07 00 00 ff 55 f8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}