
rule Trojan_Win32_Webnav_A_dll{
	meta:
		description = "Trojan:Win32/Webnav.A!dll,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {b8 93 24 49 92 f7 e9 03 d1 c1 fa 04 8b fa c1 ef 1f 03 fa } //2
		$a_01_1 = {3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 69 6e 64 65 78 2e 68 74 6d 6c } //1 :\windows\system32\index.html
		$a_01_2 = {33 36 30 73 65 55 52 4c 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 360seURL\shell\open\command
		$a_01_3 = {3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 77 69 73 65 73 6f 66 74 5c 00 } //1
		$a_01_4 = {68 74 6d 6c 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 htmlfile\shell\open\command
		$a_01_5 = {45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 22 20 22 25 31 22 } //1 Explorer\iexplore.exe" "%1"
		$a_01_6 = {5c 77 69 73 65 73 6f 66 74 5c 63 6f 6e 66 69 67 2e 69 6e 69 } //1 \wisesoft\config.ini
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}