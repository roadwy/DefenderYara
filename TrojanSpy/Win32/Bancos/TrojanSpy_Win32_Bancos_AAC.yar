
rule TrojanSpy_Win32_Bancos_AAC{
	meta:
		description = "TrojanSpy:Win32/Bancos.AAC,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 00 54 00 57 00 4f 00 42 00 52 00 4f 00 } //01 00  TTWOBRO
		$a_01_1 = {54 74 77 6f 62 72 6f 06 74 77 6f 62 72 6f } //01 00  瑔潷牢ٯ睴扯潲
		$a_01_2 = {4d 00 61 00 69 00 6e 00 5a 00 69 00 6f 00 6e 00 } //32 00  MainZion
		$a_03_3 = {66 ba bf 07 b8 90 01 04 e8 90 01 04 8d 90 01 02 66 ba bf 07 b8 90 01 04 e8 90 01 04 8d 90 01 02 66 ba bf 07 b8 90 01 04 e8 90 01 04 8d 90 00 } //32 00 
		$a_03_4 = {c1 eb 08 66 33 cb 66 90 02 19 66 69 c0 01 d2 66 05 6a 7f 66 90 00 } //32 00 
		$a_03_5 = {c1 e9 08 66 33 d1 66 90 02 14 66 69 c6 01 d2 66 05 6a 7f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}