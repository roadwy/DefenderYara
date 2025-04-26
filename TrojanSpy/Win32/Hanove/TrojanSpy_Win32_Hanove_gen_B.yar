
rule TrojanSpy_Win32_Hanove_gen_B{
	meta:
		description = "TrojanSpy:Win32/Hanove.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {5c 48 61 6e 67 4f 76 65 72 [0-30] 2e 70 64 62 00 } //2
		$a_01_1 = {00 45 4d 53 46 52 54 43 42 56 44 00 } //2 䔀卍剆䍔噂D
		$a_01_2 = {fe 08 40 80 38 00 75 f8 } //1
		$a_01_3 = {48 3d f2 01 00 00 77 17 8a 14 01 80 fa 2f 74 0f 80 fa 5c 74 0a c6 44 01 01 2f c6 44 01 02 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}