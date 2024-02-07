
rule TrojanSpy_Win32_Hesperbot_L{
	meta:
		description = "TrojanSpy:Win32/Hesperbot.L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 c7 45 d4 23 2a 89 45 e0 89 5d e4 89 7d e8 89 7d ec c7 45 f0 05 00 00 00 e8 } //02 00 
		$a_01_1 = {b8 db 4b 68 2f f7 e6 8b c6 2b c2 d1 e8 03 c2 c1 e8 05 6b c0 36 8b d6 2b d0 8b 03 8a 92 } //01 00 
		$a_01_2 = {b1 19 0f e8 4c ff 58 51 51 ad 54 f7 ce fd bc 97 83 79 fa 32 cb ea 54 2d fd c3 2d 69 7e 45 0d 9d } //01 00 
		$a_01_3 = {c2 b7 71 00 e2 56 49 bc 1b be 0a 14 0d e0 3d 94 bc 92 cf f8 e5 0d a6 65 a2 84 30 42 8a b0 0d 27 } //00 00 
		$a_00_4 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}