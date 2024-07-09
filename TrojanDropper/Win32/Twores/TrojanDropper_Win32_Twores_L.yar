
rule TrojanDropper_Win32_Twores_L{
	meta:
		description = "TrojanDropper:Win32/Twores.L,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 04 30 8b 54 24 ?? 34 ?? 42 57 88 06 6a 00 89 54 24 ?? 46 ff d5 39 44 24 90 1b 00 72 e0 8b 74 24 } //1
		$a_01_1 = {6a 00 68 80 00 00 00 6a 02 6a 00 6a 02 68 00 00 00 40 } //1
		$a_00_2 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
		$a_00_3 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 } //1 SizeofResource
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}