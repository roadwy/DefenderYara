
rule Worm_Win32_Dorkbot_AM_{
	meta:
		description = "Worm:Win32/Dorkbot.AM!!Dorkbot.gen!B,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 06 32 da 32 1d 90 01 04 fe c2 88 18 40 3a d1 72 ec 90 00 } //1
		$a_01_1 = {30 14 06 41 81 f9 01 01 00 00 72 ee f6 14 06 8b c8 46 8d 79 01 } //1
		$a_03_2 = {8b f8 2b f7 8a 1c 06 32 da 32 1d 90 01 04 fe c2 88 18 40 3a d1 72 ec 90 00 } //1
		$a_01_3 = {28 00 66 00 61 00 63 00 65 00 70 00 61 00 6c 00 6d 00 29 00 } //1 (facepalm)
		$a_00_4 = {6c 00 61 00 72 00 61 00 77 00 61 00 6e 00 67 00 20 00 69 00 74 00 6f 00 } //1 larawang ito
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}