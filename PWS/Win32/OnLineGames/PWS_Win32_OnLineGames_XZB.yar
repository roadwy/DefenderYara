
rule PWS_Win32_OnLineGames_XZB{
	meta:
		description = "PWS:Win32/OnLineGames.XZB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {25 73 5c 25 73 5f 6c 25 64 (2e 6a 70 67|2e 62 6d 70) } //1
		$a_00_1 = {5c 53 68 65 6c 6c 4e 6f 52 6f 61 6d 5c 4d 55 49 43 61 63 68 65 } //1 \ShellNoRoam\MUICache
		$a_00_2 = {25 73 5c 6b 73 75 73 65 72 2e 64 6c 6c } //1 %s\ksuser.dll
		$a_00_3 = {25 73 3f 61 63 74 3d 67 65 74 70 6f 73 26 64 31 30 3d 25 73 26 70 6f 73 3d 26 64 38 30 3d 25 64 } //1 %s?act=getpos&d10=%s&pos=&d80=%d
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}