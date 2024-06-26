
rule Trojan_Win32_QHosts_C{
	meta:
		description = "Trojan:Win32/QHosts.C,SIGNATURE_TYPE_PEHSTR_EXT,37 00 36 00 0b 00 00 0a 00 "
		
	strings :
		$a_00_0 = {3e 20 6e 75 6c } //0a 00  > nul
		$a_00_1 = {2f 63 20 20 64 65 6c } //0a 00  /c  del
		$a_00_2 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //0a 00  \drivers\etc\hosts
		$a_01_3 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41 } //0a 00  GetSystemDirectoryA
		$a_00_4 = {43 6f 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 33 2d 31 39 39 39 20 4d 69 63 72 6f 73 6f 66 74 20 43 6f 72 70 2e } //01 00  Copyright (c) 1993-1999 Microsoft Corp.
		$a_00_5 = {32 37 2e 30 2e 30 2e 33 } //01 00  27.0.0.3
		$a_00_6 = {36 31 2e 31 32 39 2e 31 31 35 2e 39 30 } //01 00  61.129.115.90
		$a_00_7 = {71 71 71 2e 36 31 31 33 39 2e 63 6f 6d } //01 00  qqq.61139.com
		$a_00_8 = {77 77 77 2e 6a 62 33 31 35 2e 63 6e } //01 00  www.jb315.cn
		$a_00_9 = {77 6f 77 2e 36 31 31 33 39 2e 63 6f 6d } //01 00  wow.61139.com
		$a_00_10 = {77 77 2e 62 61 69 64 75 33 2e 63 6f 6d } //00 00  ww.baidu3.com
	condition:
		any of ($a_*)
 
}