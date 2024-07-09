
rule PWS_Win32_OnLineGames_JB{
	meta:
		description = "PWS:Win32/OnLineGames.JB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {6d 50 56 c6 45 ?? 69 c6 45 ?? 62 c6 45 ?? 61 c6 45 ?? 6f c6 45 ?? 2e c6 45 ?? 61 c6 45 ?? 73 } //2
		$a_03_1 = {3f 50 8d 85 ?? ?? ?? ?? 50 c6 45 ?? 61 c6 45 ?? 63 c6 45 ?? 74 c6 45 ?? 69 c6 45 ?? 6f c6 45 ?? 6e c6 45 ?? 3d } //2
		$a_01_2 = {85 db 74 0a 8a 06 32 c2 88 06 46 4b eb f2 } //1
		$a_03_3 = {3f 5b c6 45 ?? 64 c6 45 ?? ?? c6 45 ?? 3d c6 45 ?? 25 c6 45 ?? 73 } //2
		$a_00_4 = {25 73 2f 62 6d 70 2f 25 73 5f 6d 69 62 61 6f 6b 61 2e 62 6d 70 } //1 %s/bmp/%s_mibaoka.bmp
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2+(#a_00_4  & 1)*1) >=4
 
}