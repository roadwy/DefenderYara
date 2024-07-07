
rule TrojanSpy_Win32_Cutwail_gen_D{
	meta:
		description = "TrojanSpy:Win32/Cutwail.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c0 05 50 68 90 01 04 8d 77 21 6a 08 56 ff 15 90 01 04 83 c4 1c eb 01 46 80 3e 00 75 fa 6a 09 68 90 00 } //2
		$a_03_1 = {57 68 93 1f 00 00 68 90 01 04 e8 90 00 } //1
		$a_01_2 = {c6 45 fe 01 3c 0a 75 21 38 5d ff 74 1c 6a 08 41 68 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}