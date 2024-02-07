
rule PWS_Win32_OnLineGames_AQ{
	meta:
		description = "PWS:Win32/OnLineGames.AQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {99 f7 ff 8b 44 24 10 8a 04 02 32 01 34 90 01 01 46 3b 74 24 14 88 01 7c dd 90 00 } //02 00 
		$a_01_1 = {3c ff 74 1c 57 ff d6 3c 30 59 7c f4 3c 39 7f f0 8b 4d fc ff 45 fc 83 7d fc 06 88 44 0d f4 7c e0 } //01 00 
		$a_03_2 = {83 c0 05 0f b7 f0 c1 e6 10 8b 85 90 01 02 ff ff 83 c0 05 0f b7 c0 0b f0 89 b5 90 01 02 ff ff 56 6a 01 68 01 02 00 00 90 00 } //01 00 
		$a_01_3 = {d3 d0 c3 dc b1 a3 00 } //01 00 
		$a_01_4 = {72 65 3d 25 73 26 73 3d 25 73 26 41 3d 25 73 26 50 3d 25 73 26 4d 42 3d 25 73 } //01 00  re=%s&s=%s&A=%s&P=%s&MB=%s
		$a_01_5 = {3d 25 64 26 6d 61 63 3d 25 73 26 52 47 31 3d 25 64 26 5a 3d 25 73 3a 25 73 00 } //00 00  ┽♤慭㵣猥刦ㅇ┽♤㵚猥┺s
	condition:
		any of ($a_*)
 
}