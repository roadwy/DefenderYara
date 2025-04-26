
rule PWS_Win32_OnLineGames_JI{
	meta:
		description = "PWS:Win32/OnLineGames.JI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 56 c6 45 ?? 6d c6 45 ?? 69 c6 45 ?? 62 c6 45 ?? 61 c6 45 ?? 6f c6 45 ?? 2e c6 45 ?? 61 c6 45 ?? 73 c6 45 ?? 70 } //1
		$a_03_1 = {3f 50 8d 85 ?? ?? ?? ?? 50 c6 [0-05] 61 c6 [0-05] 63 c6 [0-05] 74 c6 [0-05] 69 c6 [0-05] 6f c6 [0-05] 6e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}