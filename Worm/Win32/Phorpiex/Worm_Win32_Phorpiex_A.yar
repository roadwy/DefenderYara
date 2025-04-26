
rule Worm_Win32_Phorpiex_A{
	meta:
		description = "Worm:Win32/Phorpiex.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 44 b4 38 6a 10 8d 54 24 18 52 50 ff d3 46 81 fe f4 01 00 00 7c e9 } //1
		$a_01_1 = {83 f8 02 75 1e 8a 06 0c 20 3c 61 74 16 3c 62 74 12 } //1
		$a_01_2 = {8b c7 99 bd 07 00 00 00 f7 fd 8a 5c 3c 14 8b 44 24 4c 47 0f be 14 02 03 d6 0f b6 c3 03 c2 99 be 28 00 00 00 f7 fe 0f b7 c2 0f b7 f0 8a 44 34 14 32 c3 } //1
		$a_03_3 = {6a 00 6a 01 6a 00 6a 11 ff d3 6a 00 6a 00 6a 00 6a 56 ff 15 ?? ?? ?? ?? 0f b6 c8 51 ff d3 6a 00 6a 03 6a 2d 6a 11 ff d3 6a 00 6a 00 6a 00 6a 0d ff d3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}