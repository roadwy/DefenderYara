
rule Worm_Win32_Debllama_B{
	meta:
		description = "Worm:Win32/Debllama.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {ff d7 83 ec 10 b9 08 00 00 00 8b d4 b8 34 36 40 00 8b 1d 18 11 40 00 6a 01 89 0a 8b 8d 68 ff ff ff 68 54 36 40 00 c7 85 4c ff ff ff ff ff ff ff 89 4a 04 8d 4d dc 51 c7 85 44 ff ff ff 0b 80 00 00 } //01 00 
		$a_00_1 = {74 00 65 00 20 00 6d 00 6f 00 6c 00 65 00 73 00 74 00 61 00 6e 00 20 00 6c 00 6f 00 73 00 20 00 56 00 69 00 72 00 75 00 73 00 3f 00 3f 00 3f 00 } //01 00  te molestan los Virus???
		$a_01_2 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 3d 77 69 6e 64 2e 65 78 65 } //01 00  shell\open\command=wind.exe
		$a_01_3 = {45 4c 20 44 49 41 42 4c 4f } //01 00  EL DIABLO
		$a_00_4 = {64 00 65 00 76 00 69 00 6c 00 2e 00 76 00 62 00 70 00 } //00 00  devil.vbp
	condition:
		any of ($a_*)
 
}