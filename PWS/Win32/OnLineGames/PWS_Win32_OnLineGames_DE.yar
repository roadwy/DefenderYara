
rule PWS_Win32_OnLineGames_DE{
	meta:
		description = "PWS:Win32/OnLineGames.DE,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_00_1 = {3f 75 73 65 72 3d } //01 00  ?user=
		$a_00_2 = {66 75 63 6b } //01 00  fuck
		$a_00_3 = {26 70 77 64 3d } //01 00  &pwd=
		$a_03_4 = {8b f8 85 ff 7e 4e bb 01 00 00 00 8b 45 fc 8a 44 18 ff 24 0f 8b 55 90 01 01 8a 54 32 ff 80 e2 0f 32 c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}