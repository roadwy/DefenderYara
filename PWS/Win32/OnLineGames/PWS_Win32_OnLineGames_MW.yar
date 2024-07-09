
rule PWS_Win32_OnLineGames_MW{
	meta:
		description = "PWS:Win32/OnLineGames.MW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 68 68 66 64 2a 00 00 55 53 } //1
		$a_03_1 = {77 69 6e 30 90 04 01 02 36 37 25 30 38 78 2e 64 6c 6c 00 } //1
		$a_03_2 = {ff 2e c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 78 c6 85 ?? ?? ff ff 65 [0-06] (6a 3e f3 ab|f3 ab 6a 3e) } //1
		$a_00_3 = {8a 0e 57 33 ff 88 08 84 c9 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}