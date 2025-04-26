
rule Trojan_Win32_Farfli_GC_MTB{
	meta:
		description = "Trojan:Win32/Farfli.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 1c 32 89 55 ?? 8d 04 32 8b 45 ?? 03 c8 0f b6 04 37 0f b6 d3 03 c2 [0-30] 8a 04 32 30 01 ff 45 ?? 8b 45 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Farfli_GC_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {5c 78 68 6a 6d 6a 6a 2e 64 61 74 } //1 \xhjmjj.dat
		$a_01_1 = {63 3a 5c 57 69 6e 5f 6c 6a 2e 69 6e 69 } //1 c:\Win_lj.ini
		$a_01_2 = {4e 65 74 2d 54 65 6d 70 2e 69 6e 69 } //1 Net-Temp.ini
		$a_01_3 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 73 6f 75 67 6f 75 } //1 %SystemRoot%\System32\svchost.exe -k sougou
		$a_01_4 = {54 4f 58 48 4a 20 4d 59 4c 4f 56 45 } //1 TOXHJ MYLOVE
		$a_80_5 = {77 6c 64 6c 6f 67 2e 64 6c 6c } //wldlog.dll  1
		$a_01_6 = {58 68 6a 6d 6a 20 53 68 65 6e 6a 69 } //1 Xhjmj Shenji
		$a_01_7 = {4d 6a 6a 78 68 6a 5f 5f 42 6a 6e 6c } //1 Mjjxhj__Bjnl
		$a_01_8 = {73 6f 66 74 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 48 6f 73 74 } //1 softWARE\Microsoft\Windows NT\CurrentVersion\SvcHost
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_80_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}