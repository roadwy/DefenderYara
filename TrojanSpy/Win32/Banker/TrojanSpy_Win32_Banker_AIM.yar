
rule TrojanSpy_Win32_Banker_AIM{
	meta:
		description = "TrojanSpy:Win32/Banker.AIM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 61 63 72 66 66 2e 64 6c 6c 00 } //01 00 
		$a_01_1 = {03 c6 83 e7 0f 76 10 3b f0 73 10 83 ef 01 0f b7 0e 8d 74 4e 02 75 f0 3b f0 72 06 5e 5f 33 c0 5d c3 } //01 00 
		$a_03_2 = {8b 55 00 c6 04 10 00 83 c0 01 3b c7 7c f2 90 90 33 c9 85 ff 7e 3b 90 90 8a 44 24 18 0f b6 d0 02 9a 90 01 04 04 01 0f b6 c0 25 0f 00 00 80 79 05 48 83 c8 f0 90 00 } //01 00 
		$a_03_3 = {83 c4 08 85 c0 0f 84 90 01 04 66 c7 00 00 00 68 90 01 04 8d 44 24 10 b9 90 01 04 ba 01 00 00 80 e8 90 01 04 83 c4 04 85 c0 0f 84 7a 01 00 00 53 8b 1d 90 01 04 55 68 90 01 04 8d 44 24 18 50 ff d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}