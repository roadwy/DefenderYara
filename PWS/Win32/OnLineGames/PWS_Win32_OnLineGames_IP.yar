
rule PWS_Win32_OnLineGames_IP{
	meta:
		description = "PWS:Win32/OnLineGames.IP,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 69 6c 6c 6d 62 } //01 00  killmb
		$a_01_1 = {2f 47 65 74 47 69 66 2e 61 73 70 } //01 00  /GetGif.asp
		$a_01_2 = {2f 6c 69 6e 2e 61 73 70 3f 52 45 3d 25 73 26 73 3d 25 73 26 61 3d 25 73 26 70 3d 25 73 26 7a 3d 25 64 26 4e 4f 3d 25 73 } //01 00  /lin.asp?RE=%s&s=%s&a=%s&p=%s&z=%d&NO=%s
		$a_01_3 = {2f 6c 69 6e 2e 61 73 70 3f 73 3d 25 73 26 61 3d 25 73 26 52 3d 25 73 26 52 47 3d 25 64 26 } //01 00  /lin.asp?s=%s&a=%s&R=%s&RG=%d&
		$a_01_4 = {2f 6d 62 2e 61 73 70 3f 61 3d 70 6f 73 74 6d 62 26 75 3d 25 73 26 6d 62 3d 25 } //00 00  /mb.asp?a=postmb&u=%s&mb=%
	condition:
		any of ($a_*)
 
}