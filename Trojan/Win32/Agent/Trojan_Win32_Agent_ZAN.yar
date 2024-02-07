
rule Trojan_Win32_Agent_ZAN{
	meta:
		description = "Trojan:Win32/Agent.ZAN,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //0a 00  CreateToolhelp32Snapshot
		$a_00_1 = {68 74 74 70 3a 2f 2f 6e 65 77 2e 37 34 39 35 37 31 2e 63 6f 6d 2f 78 69 6e 2e 74 78 74 } //0a 00  http://new.749571.com/xin.txt
		$a_02_2 = {b2 61 b1 65 c6 45 90 01 01 75 c6 45 90 01 01 72 88 45 90 01 01 c6 45 90 01 01 6d c6 45 90 01 01 2e 90 00 } //06 00 
		$a_02_3 = {8b d2 8b c9 8b c9 90 90 8b d2 8d 85 90 01 02 ff ff 68 04 01 00 00 50 6a 00 ff 15 90 01 03 00 8d 8d 90 01 02 ff ff 6a 5c 51 ff 15 90 01 03 00 90 00 } //03 00 
		$a_00_4 = {73 74 72 72 63 68 72 } //03 00  strrchr
		$a_00_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //03 00  InternetOpenA
		$a_00_6 = {57 69 6e 45 78 65 63 } //03 00  WinExec
		$a_00_7 = {23 33 32 37 37 30 } //00 00  #32770
	condition:
		any of ($a_*)
 
}