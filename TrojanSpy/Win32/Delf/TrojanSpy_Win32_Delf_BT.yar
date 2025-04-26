
rule TrojanSpy_Win32_Delf_BT{
	meta:
		description = "TrojanSpy:Win32/Delf.BT,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b c7 8b d0 03 d3 c6 02 e9 2b f0 2b f3 83 ee 05 42 89 32 8b c3 5d 5f 5e } //1
		$a_01_1 = {8b f0 89 3e 8b d6 83 c2 05 8b c3 e8 7a 00 00 00 8b d6 83 c2 04 88 02 c6 03 e9 47 89 2f 8d 44 24 04 50 8b 44 24 08 50 6a 05 } //1
		$a_01_2 = {2d 2d 2d 2f 24 24 2f 50 4f 53 54 5f 55 52 4c 3d } //1 ---/$$/POST_URL=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}