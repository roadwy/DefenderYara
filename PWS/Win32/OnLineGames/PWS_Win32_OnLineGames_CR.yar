
rule PWS_Win32_OnLineGames_CR{
	meta:
		description = "PWS:Win32/OnLineGames.CR,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1a 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {61 63 74 69 6f 6e 3d 66 72 65 73 68 26 7a 74 3d 6f 6e } //0a 00  action=fresh&zt=on
		$a_00_1 = {74 74 79 33 64 66 61 64 73 66 61 73 64 66 73 61 } //05 00  tty3dfadsfasdfsa
		$a_02_2 = {74 74 79 33 64 71 77 65 72 74 79 90 02 04 65 78 70 6c 6f 72 65 72 2e 65 78 65 90 00 } //01 00 
		$a_00_3 = {51 51 4c 6f 67 69 6e 2e 65 78 65 } //01 00  QQLogin.exe
		$a_00_4 = {74 74 79 33 64 2e 65 78 65 } //00 00  tty3d.exe
	condition:
		any of ($a_*)
 
}