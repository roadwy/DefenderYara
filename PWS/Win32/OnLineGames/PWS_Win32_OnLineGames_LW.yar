
rule PWS_Win32_OnLineGames_LW{
	meta:
		description = "PWS:Win32/OnLineGames.LW,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 73 63 72 6f 73 6f 66 74 2e 64 6c 6c } //01 00 
		$a_01_1 = {8d 45 f4 c6 45 f4 6d 50 56 c6 45 f5 69 c6 45 f6 62 c6 45 f7 61 c6 45 f8 6f c6 45 f9 2e c6 45 fa 61 c6 45 fb 73 c6 45 fc 70 } //00 00 
	condition:
		any of ($a_*)
 
}