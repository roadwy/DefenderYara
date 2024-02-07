
rule TrojanSpy_Win32_Banker_GJ{
	meta:
		description = "TrojanSpy:Win32/Banker.GJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4b 70 ba 90 01 04 8b c6 e8 ee d3 ff ff dd 43 40 d8 1d 90 01 04 df e0 9e 76 1f ff 73 44 ff 73 40 8d 55 f8 33 c0 e8 00 62 ff ff 8b 4d f8 ba 90 01 04 8b c6 e8 c1 d3 ff ff 8b 7b 20 85 ff 75 0a 83 7b 1c 00 0f 84 88 00 00 00 83 7b 1c 00 90 00 } //01 00 
		$a_01_1 = {70 72 61 71 75 65 6d 3d 00 } //01 00 
		$a_01_2 = {74 69 70 6f 3d 00 } //01 00  楴潰=
		$a_01_3 = {53 41 4e 54 2d 52 45 44 00 } //00 00 
	condition:
		any of ($a_*)
 
}