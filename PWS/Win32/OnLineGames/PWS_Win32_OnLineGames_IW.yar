
rule PWS_Win32_OnLineGames_IW{
	meta:
		description = "PWS:Win32/OnLineGames.IW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff } //01 00 
		$a_03_1 = {83 c2 41 71 05 e8 90 01 04 88 50 01 c6 00 01 8d 55 f4 8d 45 f0 e8 90 01 04 ba 90 01 04 8d 45 f0 b1 02 e8 90 01 04 8d 55 f0 8d 45 fc e8 90 01 04 8b 45 fc e8 90 01 04 50 e8 90 01 04 83 e8 03 90 00 } //01 00 
		$a_03_2 = {b8 ff 00 00 00 e8 90 01 04 8b d8 53 68 ff 00 00 00 6a 0d a1 90 01 04 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}