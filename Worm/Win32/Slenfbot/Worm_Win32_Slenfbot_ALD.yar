
rule Worm_Win32_Slenfbot_ALD{
	meta:
		description = "Worm:Win32/Slenfbot.ALD,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 83 c0 01 89 45 f8 83 7d f8 90 01 01 7d 90 01 01 8b 4d 08 03 4d f8 0f be 91 90 01 04 33 55 fc 8b 45 f4 03 45 f8 88 10 90 00 } //01 00 
		$a_01_1 = {70 69 64 67 69 6e 00 00 73 6b 79 70 65 00 00 00 6d 73 6e 6d 73 67 72 00 61 69 6d 00 } //01 00 
		$a_01_2 = {67 64 6b 57 69 6e 64 6f 77 54 6f 70 6c 65 76 65 6c } //01 00 
		$a_01_3 = {4d 53 42 4c 57 69 6e 64 6f 77 43 6c 61 73 73 00 49 4d 57 69 6e 64 6f 77 43 6c 61 73 73 } //00 00 
	condition:
		any of ($a_*)
 
}