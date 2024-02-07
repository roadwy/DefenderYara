
rule PWS_Win32_OnLineGames_CX{
	meta:
		description = "PWS:Win32/OnLineGames.CX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {67 61 6d 65 2e 65 78 65 } //01 00  game.exe
		$a_03_1 = {6a 06 50 68 8b e6 40 00 6a 01 e8 90 01 02 ff ff 68 90 01 02 00 10 8d 4c 90 01 02 6a 06 51 68 d8 a9 62 00 6a 02 90 00 } //01 00 
		$a_03_2 = {b9 09 00 00 00 be 90 01 02 00 10 8d 90 01 03 01 00 00 33 c0 f3 a5 66 a5 a4 b9 0c 00 00 00 bf 90 01 02 00 10 f3 ab 8d 90 01 03 01 00 00 68 90 01 02 00 10 52 66 ab e8 90 01 02 ff ff 83 c4 40 e8 90 01 02 ff ff a1 90 01 02 00 10 8b 0d 90 01 02 00 10 8b 15 90 01 02 00 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}