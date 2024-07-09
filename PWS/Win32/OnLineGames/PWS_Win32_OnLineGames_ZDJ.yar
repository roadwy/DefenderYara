
rule PWS_Win32_OnLineGames_ZDJ{
	meta:
		description = "PWS:Win32/OnLineGames.ZDJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 4c 04 08 80 f1 55 88 4c 04 08 40 3d 04 01 00 00 7c ed a1 ?? ?? 00 10 68 04 01 00 00 6a 00 05 ?? 01 00 00 6a 2c 8d 4c 24 14 50 51 } //1
		$a_03_1 = {8b 44 24 28 50 c7 46 ?? 01 00 00 00 [0-06] 8a 4c 24 18 8a 54 24 1c 88 4c 24 08 8a 4c 24 24 66 89 44 24 06 8a 44 24 20 88 4c 24 0b 8b ce 88 54 24 09 88 44 24 0a 66 c7 44 24 04 02 00 c7 46 ?? 01 00 00 00 c7 46 ?? 00 00 00 00 } //1
		$a_01_2 = {8a 10 8a 1e 8a ca 3a d3 75 1e 84 c9 74 16 8a 50 01 8a 5e 01 8a ca 3a d3 75 0e 83 c0 02 83 c6 02 84 c9 75 dc 33 c0 eb 05 1b c0 83 d8 ff 85 c0 } //1
		$a_03_3 = {f2 ae f7 d1 2b f9 8b f7 8b d9 8b fa 83 c9 ff f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 8d ?? 24 ?? 83 e1 03 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}