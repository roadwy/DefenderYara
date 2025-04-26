
rule PWS_Win32_OnLineGames_ZFW{
	meta:
		description = "PWS:Win32/OnLineGames.ZFW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3f c6 45 e5 64 c6 45 e6 33 c6 45 e7 3d c6 45 e8 25 c6 45 e9 73 c6 45 ea 26 } //1
		$a_01_1 = {c6 04 3b e9 8b c6 2b c3 83 e8 05 } //1
		$a_01_2 = {85 db 74 0a 8a 06 32 c2 88 06 46 4b eb f2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}