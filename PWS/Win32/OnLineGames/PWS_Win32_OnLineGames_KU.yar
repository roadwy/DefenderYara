
rule PWS_Win32_OnLineGames_KU{
	meta:
		description = "PWS:Win32/OnLineGames.KU,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 05 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f [0-25] 2f 63 68 69 6e 61 2e 61 73 70 00 } //2
		$a_01_1 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4f 75 74 6c 6f 6f 6b 20 45 78 70 72 65 73 73 5c } //1 Program Files\Outlook Express\
		$a_01_2 = {00 53 65 6e 64 20 4f 4b 21 00 } //1
		$a_03_3 = {8b 55 dc a1 ?? ?? ?? 00 b9 ?? ?? ?? 00 e8 ?? ?? ff ff e8 ?? ?? ff ff a3 ?? ?? ?? 00 6a 00 68 ?? ?? ?? 00 e8 ?? ?? ff ff 85 c0 75 [0-06] 68 ?? ?? ?? 00 68 ?? ?? ?? 00 6a 00 6a 00 e8 ?? ?? ff ff eb 1e 68 ?? ?? ?? 00 68 58 1b 00 00 6a 00 6a 00 e8 } //2
		$a_01_4 = {56 57 89 c6 89 d7 89 c8 39 f7 77 13 74 2f c1 f9 02 78 2a f3 a5 89 c1 83 e1 03 f3 a4 5f 5e } //2
	condition:
		((#a_02_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2+(#a_01_4  & 1)*2) >=6
 
}