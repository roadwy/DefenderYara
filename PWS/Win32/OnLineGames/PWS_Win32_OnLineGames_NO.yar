
rule PWS_Win32_OnLineGames_NO{
	meta:
		description = "PWS:Win32/OnLineGames.NO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {6d 50 56 c6 45 ?? 69 c6 45 ?? 62 c6 45 ?? 61 c6 45 ?? 6f c6 45 ?? 2e c6 45 ?? 61 c6 45 ?? 73 } //2
		$a_03_1 = {73 50 8d 85 ?? ?? ?? ?? 50 c6 45 ?? 3f c6 45 ?? 61 c6 45 ?? 63 c6 45 ?? 74 c6 45 ?? 69 c6 45 ?? 6f c6 45 ?? 6e c6 45 ?? 3d } //2
		$a_03_2 = {8a 1c 03 32 da 88 18 40 ff 4d ?? 89 45 ?? 75 ad } //2
		$a_00_3 = {25 73 3f 61 63 74 69 6f 6e 3d 74 65 73 74 6c 6f 63 6b 26 75 3d 25 73 } //1 %s?action=testlock&u=%s
		$a_00_4 = {25 73 3f 61 63 74 69 6f 6e 3d 64 72 6f 70 6f 66 66 26 75 3d 25 73 } //1 %s?action=dropoff&u=%s
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}