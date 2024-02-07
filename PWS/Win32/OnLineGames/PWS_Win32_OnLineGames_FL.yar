
rule PWS_Win32_OnLineGames_FL{
	meta:
		description = "PWS:Win32/OnLineGames.FL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 4a c7 04 24 90 01 01 00 00 00 90 01 35 83 c7 04 83 c6 04 83 c3 04 ff 0c 24 75 cc 90 00 } //01 00 
		$a_00_1 = {4c 65 76 65 3d 00 } //01 00  敌敶=
		$a_00_2 = {53 65 72 76 3d 00 } //00 00  敓癲=
	condition:
		any of ($a_*)
 
}