
rule PWS_Win32_OnLineGames_EX{
	meta:
		description = "PWS:Win32/OnLineGames.EX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c0 8d 7d 90 01 01 c6 45 90 01 01 e9 90 00 } //01 00 
		$a_03_1 = {33 f6 ff 75 08 89 90 01 01 0c 89 75 90 01 01 c6 45 90 01 01 60 56 68 ff 0f 1f 00 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 00 } //01 00 
		$a_01_2 = {25 73 3f 75 73 3d 25 73 26 70 73 3d 25 73 26 } //01 00  %s?us=%s&ps=%s&
		$a_01_3 = {2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}