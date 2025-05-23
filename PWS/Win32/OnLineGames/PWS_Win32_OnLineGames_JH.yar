
rule PWS_Win32_OnLineGames_JH{
	meta:
		description = "PWS:Win32/OnLineGames.JH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {71 ff 75 08 c6 45 ?? 71 c6 45 ?? 66 c6 45 ?? 66 c6 45 ?? 6f c6 45 ?? 2e c6 45 ?? 65 c6 45 ?? 78 } //1
		$a_03_1 = {80 f9 47 75 15 80 b8 ?? ?? ?? ?? 49 75 0c 80 b8 ?? ?? ?? ?? 46 75 03 } //1
		$a_03_2 = {65 50 53 c6 45 ?? 78 c6 45 ?? 70 c6 45 ?? 6c c6 45 ?? 6f } //1
		$a_03_3 = {83 f8 0a 0f 83 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 8d 85 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 59 83 25 ?? ?? ?? ?? 00 bb ?? ?? ?? ?? c6 45 ?? 3f c6 45 ?? 64 c6 45 ?? ?? c6 45 ?? 3d c6 45 ?? 25 c6 45 ?? 73 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}