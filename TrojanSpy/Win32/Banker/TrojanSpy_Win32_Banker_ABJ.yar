
rule TrojanSpy_Win32_Banker_ABJ{
	meta:
		description = "TrojanSpy:Win32/Banker.ABJ,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 4b 70 ba 90 01 04 8b c6 e8 ee d3 ff ff dd 43 40 d8 1d 90 01 04 df e0 9e 76 1f ff 73 44 ff 73 40 8d 55 f8 33 c0 e8 00 62 ff ff 8b 4d f8 ba 90 01 04 8b c6 e8 c1 d3 ff ff 8b 7b 20 85 ff 75 0a 83 7b 1c 00 0f 84 88 00 00 00 83 7b 1c 00 90 00 } //01 00 
		$a_00_1 = {73 65 6e 68 61 } //01 00 
		$a_00_2 = {53 65 23 6e 68 23 61 20 43 61 72 23 74 61 23 6f } //01 00 
		$a_00_3 = {62 61 6e 63 23 6f 20 64 6f } //01 00 
		$a_00_4 = {75 70 40 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}