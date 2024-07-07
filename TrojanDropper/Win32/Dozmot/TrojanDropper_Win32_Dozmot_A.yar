
rule TrojanDropper_Win32_Dozmot_A{
	meta:
		description = "TrojanDropper:Win32/Dozmot.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {68 f0 9b 5b 00 56 89 4c 24 30 ff d7 8b 1d 90 01 04 8d 54 24 24 6a 00 52 8d 44 24 1c 6a 0f 50 56 ff d3 90 00 } //2
		$a_01_1 = {68 24 ad 5b 00 56 89 54 24 30 ff d7 8d 44 24 24 6a 00 50 8d 4c 24 1c 6a 0f } //2
		$a_01_2 = {75 07 b8 24 ad 5b 00 eb 08 8b 44 24 10 85 c0 76 } //2
		$a_01_3 = {44 69 76 78 44 65 63 6f 64 65 72 2e 44 69 76 78 44 65 63 6f 64 65 } //1 DivxDecoder.DivxDecode
		$a_01_4 = {44 69 76 78 44 65 63 6f 64 65 00 48 6f 6f 6b 6f 66 66 00 48 6f 6f 6b 6f 6e } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}