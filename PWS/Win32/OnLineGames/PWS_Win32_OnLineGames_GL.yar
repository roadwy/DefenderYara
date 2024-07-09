
rule PWS_Win32_OnLineGames_GL{
	meta:
		description = "PWS:Win32/OnLineGames.GL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {26 6d 62 3d 6b 69 63 6b } //2 &mb=kick
		$a_03_1 = {05 c0 bb 00 00 a3 ?? ?? ?? ?? 60 e8 ?? ?? ?? ?? 61 a1 ?? ?? ?? ?? 05 b8 b3 00 00 } //1
		$a_03_2 = {05 10 bf 00 00 a3 ?? ?? ?? ?? 60 e8 ?? ?? ?? ?? 61 a1 ?? ?? ?? ?? 05 08 b7 00 00 } //1
		$a_01_3 = {3d 6a 09 50 8d 75 18 81 fb 44 24 0c 50 75 10 83 c2 03 } //1
		$a_01_4 = {3d 8b ff 0f b6 75 18 81 fb 08 41 81 e1 75 10 83 ea 11 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}