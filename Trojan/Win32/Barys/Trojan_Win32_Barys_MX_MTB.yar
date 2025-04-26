
rule Trojan_Win32_Barys_MX_MTB{
	meta:
		description = "Trojan:Win32/Barys.MX!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 00 61 00 66 00 65 00 45 00 78 00 61 00 6d 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 } //1 SafeExamBrowser
		$a_01_1 = {74 65 73 74 65 72 } //1 tester
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //1 Software\Microsoft\Windows\CurrentVersion\RunOnce
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}