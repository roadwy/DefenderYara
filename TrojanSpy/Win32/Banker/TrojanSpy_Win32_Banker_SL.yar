
rule TrojanSpy_Win32_Banker_SL{
	meta:
		description = "TrojanSpy:Win32/Banker.SL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {94 14 85 c9 74 0c 39 08 75 08 89 cf 8b 41 fc 4a eb 02 31 c0 8b 4c 94 14 85 c9 74 0b } //01 00 
		$a_03_1 = {c1 e0 06 03 d8 89 90 01 02 83 c7 06 83 ff 08 7c 90 01 01 83 ef 08 8b cf 8b 90 01 02 d3 eb 8b cf b8 01 00 00 00 d3 e0 8b c8 8b 90 01 02 99 f7 f9 90 00 } //01 00 
		$a_00_2 = {73 61 6e 6f 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 75 73 65 72 6e 61 6d 65 70 61 73 73 77 6f 72 64 07 69 64 73 6f 63 6b 73 } //01 00 
		$a_00_3 = {62 72 61 64 65 73 63 6f } //01 00  bradesco
		$a_00_4 = {42 61 69 78 61 6e 64 6f 20 64 65 } //00 00  Baixando de
	condition:
		any of ($a_*)
 
}