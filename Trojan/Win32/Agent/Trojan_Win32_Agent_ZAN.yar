
rule Trojan_Win32_Agent_ZAN{
	meta:
		description = "Trojan:Win32/Agent.ZAN,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 08 00 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //10 CreateToolhelp32Snapshot
		$a_00_1 = {68 74 74 70 3a 2f 2f 6e 65 77 2e 37 34 39 35 37 31 2e 63 6f 6d 2f 78 69 6e 2e 74 78 74 } //10 http://new.749571.com/xin.txt
		$a_02_2 = {b2 61 b1 65 c6 45 ?? 75 c6 45 ?? 72 88 45 ?? c6 45 ?? 6d c6 45 ?? 2e } //10
		$a_02_3 = {8b d2 8b c9 8b c9 90 90 8b d2 8d 85 ?? ?? ff ff 68 04 01 00 00 50 6a 00 ff 15 ?? ?? ?? 00 8d 8d ?? ?? ff ff 6a 5c 51 ff 15 ?? ?? ?? 00 } //6
		$a_00_4 = {73 74 72 72 63 68 72 } //3 strrchr
		$a_00_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //3 InternetOpenA
		$a_00_6 = {57 69 6e 45 78 65 63 } //3 WinExec
		$a_00_7 = {23 33 32 37 37 30 } //3 #32770
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_02_2  & 1)*10+(#a_02_3  & 1)*6+(#a_00_4  & 1)*3+(#a_00_5  & 1)*3+(#a_00_6  & 1)*3+(#a_00_7  & 1)*3) >=31
 
}