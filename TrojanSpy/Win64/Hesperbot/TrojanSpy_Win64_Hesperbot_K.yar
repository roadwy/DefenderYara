
rule TrojanSpy_Win64_Hesperbot_K{
	meta:
		description = "TrojanSpy:Win64/Hesperbot.K,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 b8 f7 b6 98 63 bb a6 ba 79 49 f7 e0 48 2b ca 48 d1 e9 48 03 ca 48 c1 e9 0c 48 8b c1 } //01 00 
		$a_01_1 = {b8 ab aa aa 2a f7 e9 8b c2 c1 e8 1f 03 d0 8d 04 52 03 c0 2b c8 48 63 c1 } //01 00 
		$a_01_2 = {b8 56 55 55 55 f7 2f 8b c2 c1 e8 1f 03 d0 03 d2 3b f2 7e 07 } //01 00 
		$a_01_3 = {b8 37 97 3a 66 48 83 fa ff 75 13 41 8b d1 66 44 39 09 74 0a } //00 00 
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}