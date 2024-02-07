
rule Trojan_Win32_Emotet_CB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 03 00 "
		
	strings :
		$a_81_0 = {35 21 4f 2a 58 58 6e 2b 29 65 64 34 3c 51 59 69 64 69 33 50 69 4a 4e 45 3e 4b 66 76 52 25 25 35 3e 55 4e 78 3c 35 4e 6e 52 57 77 6e 36 4d 24 6b 78 6c } //03 00  5!O*XXn+)ed4<QYidi3PiJNE>KfvR%%5>UNx<5NnRWwn6M$kxl
		$a_81_1 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //03 00  CallNextHookEx
		$a_81_2 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //03 00  SetWindowsHookExA
		$a_81_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //03 00  ShellExecuteA
		$a_81_4 = {50 61 74 68 46 69 6e 64 45 78 74 65 6e 73 69 6f 6e 41 } //00 00  PathFindExtensionA
	condition:
		any of ($a_*)
 
}