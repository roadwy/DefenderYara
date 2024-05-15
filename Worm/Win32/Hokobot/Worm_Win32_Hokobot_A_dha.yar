
rule Worm_Win32_Hokobot_A_dha{
	meta:
		description = "Worm:Win32/Hokobot.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,34 00 34 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {3d 3d 67 4b 67 35 58 49 2b 42 6d 4b 3d 63 56 61 75 52 32 62 33 4e 48 49 49 56 47 62 77 42 79 55 6c 4a 6e 64 70 4e 57 5a } //0a 00  ==gKg5XI+BmK=cVauR2b3NHIIVGbwByUlJndpNWZ
		$a_01_1 = {53 65 74 57 69 6e 48 6f 4b } //0a 00  SetWinHoK
		$a_01_2 = {5b 61 75 74 6f 72 75 6e 5d } //0a 00  [autorun]
		$a_01_3 = {44 4c 44 2d 53 3a } //0a 00  DLD-S:
		$a_01_4 = {44 4c 44 2d 45 3a } //0a 00  DLD-E:
		$a_01_5 = {5c 25 73 2d 25 69 2e 25 69 2e 25 69 2e 25 69 2e 25 69 2e 25 69 2e 73 79 73 } //01 00  \%s-%i.%i.%i.%i.%i.%i.sys
		$a_01_6 = {3a 5c 61 75 74 6f 72 75 6e 2e 65 78 65 } //01 00  :\autorun.exe
		$a_01_7 = {23 23 44 61 74 61 23 23 3a 20 41 63 74 69 76 65 20 57 69 6e 64 6f 77 2d 2d 3e } //00 00  ##Data##: Active Window-->
		$a_00_8 = {5d 04 00 00 43 33 03 80 5c 25 00 00 44 33 03 80 00 00 01 00 08 00 0f 00 ac 21 48 6f 6b 6f 62 6f 74 2e 41 21 64 68 61 00 00 02 40 05 82 70 00 04 00 67 } //16 00 
	condition:
		any of ($a_*)
 
}