
rule PWS_Win32_OnLineGames_ABE{
	meta:
		description = "PWS:Win32/OnLineGames.ABE,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 72 78 6a 68 2e 63 6f 6d 2e 63 6e } //1 .rxjh.com.cn
		$a_01_1 = {55 73 65 72 3d 25 73 26 50 61 73 73 3d 25 73 26 53 65 72 76 65 72 3d 25 73 2d 25 73 2d 25 64 26 52 6f 6c 65 3d 25 73 } //1 User=%s&Pass=%s&Server=%s-%s-%d&Role=%s
		$a_01_2 = {79 62 5f 6d 65 6d 2e 64 6c 6c } //1 yb_mem.dll
		$a_01_3 = {25 73 28 25 73 2d 25 64 29 } //1 %s(%s-%d)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}