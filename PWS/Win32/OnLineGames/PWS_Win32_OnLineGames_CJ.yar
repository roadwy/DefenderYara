
rule PWS_Win32_OnLineGames_CJ{
	meta:
		description = "PWS:Win32/OnLineGames.CJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 } //1
		$a_01_1 = {73 74 61 72 74 20 57 6d 64 6d 50 6d 53 4e 00 } //1
		$a_01_2 = {73 74 6f 70 20 57 6d 64 6d 50 6d 53 4e 00 } //1 瑳灯圠摭偭卭N
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule PWS_Win32_OnLineGames_CJ_2{
	meta:
		description = "PWS:Win32/OnLineGames.CJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2e 64 6c 6c 00 68 6f 6f 6b 6f 66 66 00 68 6f 6f 6b 6f 6e } //1
		$a_03_1 = {6a 00 52 8d ?? ?? ?? ?? 00 00 68 14 01 00 00 50 56 ff 15 24 20 40 00 } //1
		$a_03_2 = {68 b8 0b 00 00 f3 ab ff 15 ?? ?? 40 00 8d ?? ?? ?? 51 68 04 01 00 00 ff 15 ?? ?? 40 00 8d ?? ?? ?? 68 ?? ?? 40 00 52 ff 15 ?? ?? 40 00 8d ?? ?? ?? 50 6a 6b e8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}