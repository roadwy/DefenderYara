
rule TrojanSpy_Win32_Tougle_C_bit{
	meta:
		description = "TrojanSpy:Win32/Tougle.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 07 33 d2 b9 0a 00 00 00 f7 f1 b8 cd cc cc cc 83 c3 01 80 c2 30 88 54 33 ff f7 27 c1 ea 03 85 d2 89 17 77 db } //01 00 
		$a_01_1 = {0f b6 14 31 30 14 30 8a 14 30 30 14 31 8a 14 31 30 14 30 83 e9 01 83 c0 01 8b d1 2b d0 83 fa 01 7d de } //01 00 
		$a_03_2 = {33 c0 89 07 89 47 04 6a 04 89 47 08 8d 54 24 20 53 89 47 0c 52 66 89 47 10 e8 90 01 03 00 6a 10 8d 43 04 50 57 e8 90 01 03 00 56 83 c3 14 53 55 e8 90 01 03 00 90 00 } //01 00 
		$a_01_3 = {6a 40 68 00 10 00 00 50 6a 00 ff 55 c0 85 c0 8b 5d c8 89 03 0f 84 df 00 00 00 0f b7 4e 06 85 c9 8b 56 54 7e 19 8d 77 14 8b f9 8b 0e 85 c9 74 06 3b ca 73 02 8b d1 83 c6 28 } //00 00 
	condition:
		any of ($a_*)
 
}