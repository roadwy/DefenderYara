
rule Worm_Win32_Bancorkut_B{
	meta:
		description = "Worm:Win32/Bancorkut.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {0f b6 44 10 ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 f0 7d 03 46 eb 05 be 01 00 00 00 8b 45 e8 0f b6 44 30 ff 33 d8 8d 45 cc 50 89 5d d0 c6 45 d4 00 8d 55 d0 33 c9 } //01 00 
		$a_03_1 = {ff 6a 00 68 90 01 03 00 6a 00 56 e8 90 01 03 ff 8b f8 6a 00 68 90 01 03 00 6a 00 57 e8 90 01 03 ff 8b f8 6a 00 68 90 01 03 00 6a 00 57 e8 90 01 03 ff 8b f8 6a 03 56 e8 90 01 03 ff 8b c3 e8 90 08 00 0a 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 90 00 } //02 00 
		$a_02_2 = {2a 2e 64 62 78 90 01 0b 43 3a 5c 90 02 3c 64 62 78 90 01 09 2a 2e 77 61 62 90 01 0b 77 61 62 90 01 09 2a 2e 6d 62 78 90 01 0b 6d 62 78 90 01 09 2a 2e 65 6d 6c 90 00 } //01 00 
		$a_00_3 = {77 77 77 2e 6f 72 6b 75 74 2e 63 6f 6d } //00 00  www.orkut.com
	condition:
		any of ($a_*)
 
}