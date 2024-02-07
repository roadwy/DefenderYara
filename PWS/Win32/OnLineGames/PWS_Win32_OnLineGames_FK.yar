
rule PWS_Win32_OnLineGames_FK{
	meta:
		description = "PWS:Win32/OnLineGames.FK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 3f 75 73 3d 25 73 26 70 73 3d 25 73 } //01 00  s?us=%s&ps=%s
		$a_01_1 = {70 6f 6c 63 6f 72 65 2e 64 6c 6c } //01 00  polcore.dll
		$a_01_2 = {2f 66 66 78 69 2f 6d 61 69 6c 2e 61 73 70 } //02 00  /ffxi/mail.asp
		$a_01_3 = {05 cb 4a 04 00 6a 01 50 } //02 00 
		$a_01_4 = {33 c0 80 7d ff e8 0f 94 c0 } //03 00 
		$a_01_5 = {c6 45 a8 60 c6 45 a9 6a c6 45 aa 1e c6 45 ab 8b } //02 00 
		$a_01_6 = {bf e8 03 00 00 57 ff d6 57 eb fb 57 68 } //00 00 
	condition:
		any of ($a_*)
 
}