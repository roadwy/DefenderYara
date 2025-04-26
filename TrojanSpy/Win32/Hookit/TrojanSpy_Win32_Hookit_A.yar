
rule TrojanSpy_Win32_Hookit_A{
	meta:
		description = "TrojanSpy:Win32/Hookit.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {81 c2 47 86 c8 61 8b f2 83 e6 03 8b 34 b7 8b f8 c1 ef 05 8b d8 c1 e3 04 0f ce } //1
		$a_01_1 = {3d 53 cf 99 ec 74 f4 3d c9 8a 64 6b 74 ed 33 c9 3d 8e 38 f8 79 0f 94 c1 8b c1 c9 c3 } //1
		$a_01_2 = {8d 74 06 05 80 3e e9 74 f4 8b 06 3d 8b ff 55 8b 74 07 3d cc ff 55 8b 75 32 } //1
		$a_01_3 = {2b fe 6a 05 83 ef 05 56 c6 06 e9 89 7e 01 ff d3 b0 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}