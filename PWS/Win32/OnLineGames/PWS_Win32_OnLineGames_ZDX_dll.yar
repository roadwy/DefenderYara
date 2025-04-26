
rule PWS_Win32_OnLineGames_ZDX_dll{
	meta:
		description = "PWS:Win32/OnLineGames.ZDX!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {68 80 3e 00 00 ff 15 24 19 00 10 e9 4b ff ff ff e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? f7 d8 1b c0 40 c3 } //1
		$a_03_1 = {57 56 c6 45 ?? 8b c6 45 ?? 4d c6 45 ?? 0c c6 45 ?? 8b c6 45 ?? 75 c6 45 ?? 10 c6 45 ?? 8a c6 45 ?? 45 c6 45 ?? 18 e8 } //1
		$a_01_2 = {75 70 2f 55 70 66 2e 61 73 70 } //1 up/Upf.asp
		$a_01_3 = {25 73 25 73 3f 61 63 3d 68 26 69 3d 25 73 26 68 3d 25 73 } //1 %s%s?ac=h&i=%s&h=%s
		$a_01_4 = {25 73 25 73 3f 63 3d 71 26 69 3d 25 73 26 73 3d 25 73 26 61 3d 25 73 26 6d 3d 25 73 26 74 3d 25 64 } //1 %s%s?c=q&i=%s&s=%s&a=%s&m=%s&t=%d
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}