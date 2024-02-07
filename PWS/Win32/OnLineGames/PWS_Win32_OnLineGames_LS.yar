
rule PWS_Win32_OnLineGames_LS{
	meta:
		description = "PWS:Win32/OnLineGames.LS,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 61 6d 65 63 66 67 2e 69 6e 69 } //01 00  gamecfg.ini
		$a_01_1 = {44 72 61 67 6f 6e 4e 65 73 74 2e 65 78 65 } //01 00  DragonNest.exe
		$a_01_2 = {79 75 6b 73 75 73 65 72 2e 64 6c 6c } //00 00  yuksuser.dll
	condition:
		any of ($a_*)
 
}