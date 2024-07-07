
rule TrojanDropper_Win32_Emold_E{
	meta:
		description = "TrojanDropper:Win32/Emold.E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 31 0b c0 74 90 01 01 33 c0 64 8b 40 30 83 b8 b0 00 00 00 02 90 02 06 50 58 8b e4 6a 00 68 51 4f 68 57 54 90 13 b8 90 01 04 81 c0 90 01 04 ff 55 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDropper_Win32_Emold_E_2{
	meta:
		description = "TrojanDropper:Win32/Emold.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f 31 0b c0 74 90 02 03 33 c0 90 00 } //1
		$a_01_1 = {eb 59 e8 45 00 00 00 55 8b ec 52 8b 5d 10 8b 55 0c ff 72 08 8f 83 b8 00 00 00 8b 42 10 8b 4d 08 8b 09 8b 50 20 c1 c2 07 33 d1 89 50 20 01 50 24 31 48 24 89 83 b4 00 00 00 33 c0 89 43 04 89 43 08 89 43 0c 89 43 10 5a c9 c2 10 00 64 ff 30 64 89 20 9c 80 4c 24 01 01 0f 31 9d 33 c0 64 8f 00 } //1
		$a_03_2 = {6a 40 68 00 10 00 00 68 00 10 00 00 6a 00 b8 54 ca af 91 8b 75 14 ff d6 8b f8 eb 12 b9 90 01 04 f3 a4 5a 2b 55 14 89 45 14 03 d0 ff e2 e8 90 01 01 ff ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}