
rule Trojan_Win32_Startpage_RH{
	meta:
		description = "Trojan:Win32/Startpage.RH,SIGNATURE_TYPE_PEHSTR,04 00 04 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {40 73 68 64 6f 63 6c 63 2e 64 6c 6c 2c 2d 31 30 32 34 31 } //01 00  @shdoclc.dll,-10241
		$a_01_1 = {26 74 69 64 3d 31 26 64 3d 25 73 26 75 69 64 3d 25 73 26 74 3d 25 73 } //01 00  &tid=1&d=%s&uid=%s&t=%s
		$a_01_2 = {73 68 65 6c 6c 33 32 2e 64 6c 6c 2c 43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c 20 69 6e 65 74 63 70 6c 2e 63 70 6c 2c 2c 30 } //01 00  shell32.dll,Control_RunDLL inetcpl.cpl,,0
		$a_01_3 = {5c 73 68 65 6c 6c 5c ca f4 d0 d4 28 26 52 29 5c 43 6f 6d 6d 61 6e 64 } //02 00 
		$a_01_4 = {73 65 78 2d 76 69 64 65 6f 2d 6f 6e 6c 69 6e 65 2e 63 6f 6d } //02 00  sex-video-online.com
		$a_01_5 = {25 36 73 25 36 79 25 36 73 25 36 74 25 36 65 25 36 6d } //01 00  %6s%6y%6s%6t%6e%6m
		$a_01_6 = {77 7a 34 33 32 31 2e 63 6f 6d 2f 3f 73 79 73 74 65 6d } //01 00  wz4321.com/?system
		$a_01_7 = {45 78 70 6c 6f 72 65 72 5c 48 69 64 65 44 65 73 6b 74 6f 70 49 63 6f 6e 73 5c } //00 00  Explorer\HideDesktopIcons\
	condition:
		any of ($a_*)
 
}