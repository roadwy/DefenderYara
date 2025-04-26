
rule PWS_Win32_OnLineGames_JL{
	meta:
		description = "PWS:Win32/OnLineGames.JL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {7e 27 53 8b 54 24 ?? 8a 1c 11 80 c3 ?? 88 1c 11 8b 54 24 ?? 8a 1c 11 80 f3 ?? 88 1c 11 41 3b c8 7c e1 } //1
		$a_03_1 = {ba 4f 70 65 6e 50 c7 44 24 ?? 77 69 6e 69 c7 44 24 ?? 6e 65 74 2e c7 44 24 ?? 64 6c 6c 00 } //1
		$a_03_2 = {68 e0 93 04 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? b9 ff 01 00 00 33 c0 8d bd ?? ?? ?? ?? c6 85 ?? ?? ?? ?? 00 f3 ab } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}