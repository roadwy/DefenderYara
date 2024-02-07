
rule PWS_Win32_Frethog_AW{
	meta:
		description = "PWS:Win32/Frethog.AW,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {46 6f 72 74 68 67 6f 65 72 } //01 00  Forthgoer
		$a_00_1 = {25 73 5c 64 6c 6c 63 61 63 68 65 5c 25 73 2e 6a 70 67 } //01 00  %s\dllcache\%s.jpg
		$a_00_2 = {25 73 3f 61 63 74 3d 67 65 74 70 6f 73 26 64 31 30 3d 25 73 26 70 6f 73 3d 26 64 38 30 3d } //01 00  %s?act=getpos&d10=%s&pos=&d80=
		$a_00_3 = {6d 69 62 61 6f 2e 61 73 70 } //01 00  mibao.asp
		$a_00_4 = {7a 68 65 6e 67 74 75 2e 64 61 74 } //01 00  zhengtu.dat
		$a_00_5 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //01 00  Accept-Language: zh-cn
		$a_00_6 = {73 71 6d 6d 61 69 6c 00 73 71 6d 69 6d 67 } //00 00  煳浭楡l煳業杭
	condition:
		any of ($a_*)
 
}