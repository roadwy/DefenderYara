
rule PWS_Win32_OnLineGames_HS{
	meta:
		description = "PWS:Win32/OnLineGames.HS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 20 61 6d 20 76 69 72 75 73 21 20 46 75 63 6b 20 79 6f 75 20 3a 2d 29 } //01 00  G am virus! Fuck you :-)
		$a_01_1 = {79 65 73 20 26 26 20 6e 65 74 20 75 73 65 72 20 67 75 65 73 74 20 31 32 34 32 37 37 36 36 38 20 26 26 20 6e 65 74 } //01 00  yes && net user guest 124277668 && net
		$a_01_2 = {53 75 70 65 72 2d 58 } //00 00  Super-X
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_OnLineGames_HS_2{
	meta:
		description = "PWS:Win32/OnLineGames.HS,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 8a 1c 11 80 c3 7a 88 1c 11 8b 55 fc 80 34 11 19 90 02 08 41 3b c8 7c 90 00 } //01 00 
		$a_01_1 = {77 49 4e 44 4f 57 53 20 6e 74 5c 63 55 52 52 45 4e 54 76 45 52 53 49 4f 4e 5c 73 56 43 48 4f 53 54 } //01 00  wINDOWS nt\cURRENTvERSION\sVCHOST
		$a_01_2 = {25 73 59 53 54 45 4d 72 4f 4f 54 25 5c 73 59 53 54 45 4d 33 32 5c 53 56 43 48 4f 53 54 2e 45 58 45 20 2d 4b 20 4e 45 54 53 56 43 53 } //01 00  %sYSTEMrOOT%\sYSTEM32\SVCHOST.EXE -K NETSVCS
		$a_01_3 = {53 75 70 65 72 58 } //00 00  SuperX
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_OnLineGames_HS_3{
	meta:
		description = "PWS:Win32/OnLineGames.HS,SIGNATURE_TYPE_PEHSTR,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 25 73 20 25 73 2c 25 73 20 25 73 } //01 00  cmd /c %s %s,%s %s
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 42 6c 69 7a 7a 61 72 64 20 45 6e 74 65 72 74 61 69 6e 6d 65 6e 74 5c 57 6f 72 6c 64 20 6f 66 20 57 61 72 63 72 61 66 74 } //01 00  SOFTWARE\Blizzard Entertainment\World of Warcraft
		$a_01_2 = {77 69 6e 6f 77 61 74 65 72 2e 65 78 65 } //01 00  winowater.exe
		$a_01_3 = {52 61 76 4d 6f 6e 44 2e 65 78 65 } //01 00  RavMonD.exe
		$a_01_4 = {54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //00 00  TerminateProcess
	condition:
		any of ($a_*)
 
}