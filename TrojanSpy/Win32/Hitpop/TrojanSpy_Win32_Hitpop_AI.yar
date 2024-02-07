
rule TrojanSpy_Win32_Hitpop_AI{
	meta:
		description = "TrojanSpy:Win32/Hitpop.AI,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1e 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 54 3a ff 33 c2 89 45 f8 8d 45 dc 8b 55 f8 e8 90 01 04 8b 55 dc 8b c6 e8 90 01 04 47 4b 75 b0 90 00 } //0a 00 
		$a_00_1 = {6c 6c 6a 79 6e 64 66 33 32 } //0a 00  lljyndf32
		$a_02_2 = {6d 79 64 6f 77 6e 2e 61 73 70 3f 76 65 72 3d 90 02 06 26 74 67 69 64 3d 90 02 10 26 61 64 64 72 65 73 73 3d 30 30 2d 30 30 2d 30 30 2d 30 30 2d 30 30 2d 30 30 90 00 } //01 00 
		$a_00_3 = {38 6b 61 6b 61 2e 63 6f 6d } //00 00  8kaka.com
	condition:
		any of ($a_*)
 
}