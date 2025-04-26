
rule Trojan_Win32_Kriskynote_B_dha{
	meta:
		description = "Trojan:Win32/Kriskynote.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 69 6e 67 4f 66 50 68 61 6e 74 6f 6d 30 33 30 38 5f 32 30 31 34 30 38 32 36 } //2 KingOfPhantom0308_20140826
		$a_01_1 = {56 56 ff 74 24 14 89 44 24 1c 50 57 ff d3 50 57 56 56 ff d5 8b 44 24 10 5e } //1
		$a_01_2 = {57 48 83 ec 40 b8 01 00 00 00 3b d0 0f 85 fd 00 00 00 ff 15 3e 10 00 00 85 c0 0f 84 e3 00 00 00 83 64 24 58 00 ff 15 d3 0f 00 00 48 8d 54 24 58 48 8b c8 ff 15 15 10 00 00 b9 02 00 00 00 39 4c 24 58 48 8b f0 0f 8c b8 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Kriskynote_B_dha_2{
	meta:
		description = "Trojan:Win32/Kriskynote.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 00 74 00 65 00 6d 00 70 00 25 00 5c 00 63 00 68 00 6b 00 5f 00 68 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 5f 00 73 00 74 00 61 00 74 00 65 00 2e 00 64 00 6c 00 6c 00 } //2 %temp%\chk_harddisk_state.dll
		$a_01_1 = {45 00 6c 00 65 00 76 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 21 00 6e 00 65 00 77 00 3a 00 7b 00 33 00 61 00 64 00 30 00 35 00 35 00 37 00 35 00 2d 00 38 00 38 00 35 00 37 00 2d 00 34 00 38 00 35 00 30 00 2d 00 39 00 32 00 37 00 37 00 2d 00 31 00 31 00 62 00 38 00 35 00 62 00 64 00 62 00 38 00 65 00 30 00 39 00 7d 00 } //1 Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}