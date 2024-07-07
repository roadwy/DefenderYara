
rule Worm_Win32_Dorkbot_AV{
	meta:
		description = "Worm:Win32/Dorkbot.AV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b f8 2b f7 8a 1c 06 32 da 32 1d 90 01 04 fe c2 88 18 40 3a d1 72 ec 90 00 } //1
		$a_03_1 = {8a 0c 39 32 0d 90 01 04 32 4d ff fe 45 ff 88 0f 47 38 45 ff 72 e6 90 00 } //1
		$a_01_2 = {30 14 06 41 81 f9 01 01 00 00 72 ee f6 14 06 8b c8 46 8d 79 01 } //1
		$a_01_3 = {28 00 66 00 61 00 63 00 65 00 70 00 61 00 6c 00 6d 00 29 00 } //1 (facepalm)
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}