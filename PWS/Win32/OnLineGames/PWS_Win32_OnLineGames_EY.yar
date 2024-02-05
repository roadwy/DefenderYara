
rule PWS_Win32_OnLineGames_EY{
	meta:
		description = "PWS:Win32/OnLineGames.EY,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {59 8d bd b8 f0 ff ff f3 a5 66 a5 b9 c9 03 00 00 33 c0 8d bd ce f0 ff ff 68 90 01 04 f3 ab 66 ab 8d 85 b8 f0 ff ff 68 90 01 04 50 e8 90 00 } //01 00 
		$a_00_1 = {68 74 74 70 3a 2f 2f 24 31 25 73 24 31 3a 25 64 25 73 3f 25 73 } //01 00 
		$a_00_2 = {25 73 24 31 25 73 24 31 2a 24 31 2e 64 6c 6c } //01 00 
		$a_00_3 = {64 72 69 24 31 76 65 72 73 5c 65 24 31 74 63 5c 68 6f 73 24 31 74 73 } //00 00 
	condition:
		any of ($a_*)
 
}