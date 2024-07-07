
rule Trojan_Win32_Zlob_ZWJ{
	meta:
		description = "Trojan:Win32/Zlob.ZWJ,SIGNATURE_TYPE_PEHSTR_EXT,41 00 41 00 0d 00 00 "
		
	strings :
		$a_01_0 = {56 41 43 2e 56 69 64 65 6f 00 } //20 䅖⹃楖敤o
		$a_00_1 = {00 72 65 66 72 2e 64 6c 6c } //20
		$a_00_2 = {25 73 5c 6c 61 25 73 25 64 2e 65 78 65 } //10 %s\la%s%d.exe
		$a_00_3 = {00 63 68 65 63 6b 00 63 6f 70 79 00 72 75 6e 00 } //10 挀敨正挀灯y畲n
		$a_01_4 = {48 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 } //1 HttpOpenRequest
		$a_00_5 = {69 6e 74 65 72 6e 65 74 63 72 61 63 6b 75 72 6c 61 } //1 internetcrackurla
		$a_00_6 = {66 69 6e 64 66 69 72 73 74 75 72 6c 63 61 63 68 65 65 6e 74 72 79 61 } //1 findfirsturlcacheentrya
		$a_00_7 = {46 69 6e 64 43 6c 6f 73 65 55 72 6c 43 61 63 68 65 } //1 FindCloseUrlCache
		$a_01_8 = {52 65 67 43 72 65 61 74 65 4b 65 79 } //1 RegCreateKey
		$a_00_9 = {73 68 65 6c 6c 65 78 65 63 75 74 65 41 } //1 shellexecuteA
		$a_00_10 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1 Software\Microsoft\Windows\CurrentVersion
		$a_00_11 = {4e 75 6c 6c 73 6f 66 74 49 6e 73 74 } //1 NullsoftInst
		$a_00_12 = {53 6f 66 74 77 61 72 65 5c 4f 6e 6c 69 6e 65 20 41 64 64 2d 6f 6e } //1 Software\Online Add-on
	condition:
		((#a_01_0  & 1)*20+(#a_00_1  & 1)*20+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_01_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1) >=65
 
}