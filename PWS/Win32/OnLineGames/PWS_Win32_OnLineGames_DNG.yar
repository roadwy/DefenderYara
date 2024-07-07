
rule PWS_Win32_OnLineGames_DNG{
	meta:
		description = "PWS:Win32/OnLineGames.DNG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {39 1e 74 26 8b c9 8b d2 8b c9 8b c0 90 8b c9 8b c9 8b d2 8b c9 8b c0 90 8b c9 57 ff 16 59 85 c0 75 08 } //1
		$a_01_1 = {6a 06 50 57 56 c6 45 f8 50 c6 45 f9 68 c6 45 fa f9 c6 45 fb e9 c6 45 fc be e8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}