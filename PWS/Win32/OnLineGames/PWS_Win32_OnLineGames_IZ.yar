
rule PWS_Win32_OnLineGames_IZ{
	meta:
		description = "PWS:Win32/OnLineGames.IZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {85 db 74 0a 8a 06 32 c2 88 06 46 4b eb f2 } //01 00 
		$a_03_1 = {83 ff 78 0f 82 90 01 04 83 fe 64 0f 82 90 00 } //01 00 
		$a_01_2 = {c6 04 3b e9 8b c6 2b c3 83 e8 05 } //00 00 
	condition:
		any of ($a_*)
 
}