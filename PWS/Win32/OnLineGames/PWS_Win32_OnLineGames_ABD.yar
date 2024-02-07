
rule PWS_Win32_OnLineGames_ABD{
	meta:
		description = "PWS:Win32/OnLineGames.ABD,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_02_0 = {4e 61 6d 65 3d 25 73 26 50 61 73 73 90 02 05 3d 25 73 26 90 02 20 26 4c 65 76 65 6c 3d 25 73 26 4d 6f 6e 65 79 3d 25 73 26 59 42 3d 25 73 26 90 02 20 3d 25 73 26 4d 42 3d 25 73 26 90 02 20 3d 25 73 26 90 02 20 3d 25 73 26 90 02 20 3d 25 73 26 90 02 20 3d 25 73 26 90 02 40 76 65 72 3d 25 73 90 00 } //01 00 
		$a_01_1 = {26 53 65 72 76 65 72 3d 25 73 } //01 00  &Server=%s
		$a_01_2 = {26 5a 6f 6e 65 3d 25 73 } //01 00  &Zone=%s
		$a_00_3 = {26 53 74 61 74 65 3d 32 } //01 00  &State=2
		$a_00_4 = {3f 61 63 74 69 6f 6e 3d 26 4e 61 6d 65 3d } //01 00  ?action=&Name=
		$a_00_5 = {73 65 72 76 65 72 6e 61 6d 65 } //01 00  servername
		$a_00_6 = {5c 63 6f 6e 66 69 67 2e 69 6e 69 } //01 00  \config.ini
		$a_00_7 = {47 65 74 6d 62 2e 61 73 70 } //00 00  Getmb.asp
	condition:
		any of ($a_*)
 
}