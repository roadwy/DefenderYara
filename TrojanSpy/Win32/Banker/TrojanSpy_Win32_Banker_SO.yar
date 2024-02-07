
rule TrojanSpy_Win32_Banker_SO{
	meta:
		description = "TrojanSpy:Win32/Banker.SO,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {94 14 85 c9 74 0c 39 08 75 08 89 cf 8b 41 fc 4a eb 02 31 c0 8b 4c 94 14 85 c9 74 0b } //01 00 
		$a_00_1 = {73 61 6e 6f 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 75 73 65 72 6e 61 6d 65 70 61 73 73 77 6f 72 64 07 69 64 73 6f 63 6b 73 } //01 00 
		$a_00_2 = {2e 63 6f 6d 2e 62 72 } //01 00  .com.br
		$a_00_3 = {63 61 6d 69 6e 68 6f } //01 00  caminho
		$a_00_4 = {70 72 61 71 75 65 6d 3d } //01 00  praquem=
		$a_00_5 = {6c 6f 67 61 61 2e 64 6c 6c } //00 00  logaa.dll
	condition:
		any of ($a_*)
 
}