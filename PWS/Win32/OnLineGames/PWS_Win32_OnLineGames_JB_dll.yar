
rule PWS_Win32_OnLineGames_JB_dll{
	meta:
		description = "PWS:Win32/OnLineGames.JB!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {57 56 c6 45 ?? 8b c6 45 ?? 4d c6 45 ?? 0c c6 45 ?? 8b c6 45 ?? 75 c6 45 ?? 10 c6 45 ?? 8a c6 45 ?? 45 c6 45 ?? 18 } //1
		$a_03_1 = {57 56 c6 45 ?? 40 c6 45 ?? 83 c6 45 ?? c1 c6 45 ?? 03 c6 45 ?? 83 c6 45 ?? c2 c6 45 ?? 08 c6 45 ?? 83 c6 45 ?? f8 c6 45 ?? 03 c6 45 ?? 7c c6 45 ?? e1 c6 45 } //1
		$a_01_2 = {75 70 2f 55 70 66 2e 61 73 70 } //1 up/Upf.asp
		$a_01_3 = {25 73 25 73 3f 63 3d 71 26 69 3d 25 73 26 73 3d 25 73 26 61 3d 25 73 26 6d 3d 25 73 26 74 3d 25 } //1 %s%s?c=q&i=%s&s=%s&a=%s&m=%s&t=%
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}