
rule Trojan_Win32_Gozi_BA_MTB{
	meta:
		description = "Trojan:Win32/Gozi.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {b8 04 00 00 00 6b c8 12 81 b9 90 01 04 b5 18 00 00 75 42 ba 04 00 00 00 c1 e2 02 90 02 30 81 e9 1d 9b 00 00 0f b6 15 90 01 04 2b ca 03 0d 90 00 } //01 00 
		$a_02_1 = {b9 04 00 00 00 6b d1 09 b8 04 00 00 00 c1 e0 00 90 02 15 81 f9 a4 02 00 00 90 00 } //01 00 
		$a_81_2 = {4e 6f 6f 6e 2e 64 6c 6c } //01 00  Noon.dll
		$a_81_3 = {43 6c 6f 73 65 77 68 65 74 68 65 72 } //01 00  Closewhether
		$a_81_4 = {4d 65 61 6e 74 64 75 63 6b } //01 00  Meantduck
		$a_81_5 = {52 6f 70 65 6d 61 79 } //00 00  Ropemay
	condition:
		any of ($a_*)
 
}