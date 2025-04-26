
rule PWS_Win32_OnLineGames_BG{
	meta:
		description = "PWS:Win32/OnLineGames.BG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {74 18 56 6a 32 6a 01 ff ?? ?? ff 15 } //1
		$a_03_1 = {6a 2f 57 ff 15 ?? ?? ?? ?? 40 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 32 } //1
		$a_01_2 = {25 73 25 73 25 73 } //1 %s%s%s
		$a_00_3 = {6d 69 62 61 6f 2e 61 73 70 } //1 mibao.asp
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule PWS_Win32_OnLineGames_BG_2{
	meta:
		description = "PWS:Win32/OnLineGames.BG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 45 fc e8 ?? ?? ff ff 8b 55 fc 8a 54 1a ff 80 ea ?? 88 54 18 ff 43 4e 75 e6 } //1
		$a_03_1 = {be 65 00 00 00 6a 0a e8 ?? ?? ff ff 6a 00 6a 00 6a 00 6a 08 e8 ?? ?? ff ff 6a 00 6a 02 6a 00 6a 08 e8 ?? ?? ff ff 4e 75 dc } //1
		$a_03_2 = {81 fb c8 00 00 00 7e 07 6a 00 e8 ?? ?? ?? ?? 6a 64 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 74 0a ?? ?? ?? ?? ?? ?? ?? ?? 75 03 43 eb ca } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}