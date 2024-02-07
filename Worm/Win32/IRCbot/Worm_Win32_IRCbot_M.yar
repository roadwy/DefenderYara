
rule Worm_Win32_IRCbot_M{
	meta:
		description = "Worm:Win32/IRCbot.M,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 5c 7b 25 73 2d 25 73 7d 5c 55 44 50 5f 4d 6f 64 75 6c 65 2e 64 6c 6c } //01 00  %s\{%s-%s}\UDP_Module.dll
		$a_01_1 = {25 73 5c 4d 69 63 72 6f 73 6f 66 74 5f 52 65 6d 6f 76 61 6c 5f 54 6f 6f 6c 2e 62 61 74 } //01 00  %s\Microsoft_Removal_Tool.bat
		$a_01_2 = {55 44 50 5f 46 6c 6f 6f 64 00 55 44 50 5f 46 6c 6f 6f 64 5f 50 6f 72 74 00 } //01 00 
		$a_03_3 = {4e 49 43 4b 90 01 04 4a 4f 49 4e 90 00 } //01 00 
		$a_03_4 = {50 49 4e 47 90 01 14 50 52 49 56 4d 53 47 90 00 } //01 00 
		$a_01_5 = {30 4e 65 77 20 49 6e 66 65 63 74 69 6f 6e 20 76 69 61 20 55 53 42 20 53 70 72 65 61 64 } //01 00  0New Infection via USB Spread
		$a_01_6 = {0f 55 44 50 20 4d 6f 64 75 6c 65 20 54 65 72 6d 69 6e 61 74 65 64 } //01 00 
		$a_01_7 = {3c 3c 2e 7c 2e 34 57 47 65 74 20 45 72 72 6f 72 2e 7c 2e 2e 34 3e 3e } //00 00  <<.|.4WGet Error.|..4>>
	condition:
		any of ($a_*)
 
}