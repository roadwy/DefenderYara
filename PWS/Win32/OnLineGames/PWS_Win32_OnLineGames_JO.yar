
rule PWS_Win32_OnLineGames_JO{
	meta:
		description = "PWS:Win32/OnLineGames.JO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 30 80 f3 ?? 88 1c 30 40 3d ?? ?? ?? ?? 72 ef } //1
		$a_02_1 = {b2 41 b1 4e 50 68 02 00 00 80 c6 44 24 ?? 4f 88 54 24 ?? c6 44 24 ?? 52 c6 44 24 ?? 45 c6 44 24 ?? 5c } //2
		$a_03_2 = {74 04 3c 6e 75 37 80 7c ?? ?? 2e 75 30 8a 44 ?? ?? 3c 45 } //1
		$a_03_3 = {81 c7 99 00 00 00 89 7c 24 ?? bf ?? ?? ?? ?? 8b 44 24 ?? 8d 54 24 ?? 6a 00 52 55 50 56 ff d3 4f 75 ed } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}