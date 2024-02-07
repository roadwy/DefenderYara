
rule TrojanClicker_Win32_Agent_KA{
	meta:
		description = "TrojanClicker:Win32/Agent.KA,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 43 2b 2b 20 52 75 6e 74 69 6d 65 20 4c 69 62 72 61 72 79 } //01 00  Microsoft Visual C++ Runtime Library
		$a_01_1 = {61 00 64 00 63 00 72 00 2e 00 6e 00 61 00 76 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 } //01 00  adcr.naver.com
		$a_01_2 = {63 00 6c 00 69 00 63 00 6b 00 2e 00 61 00 64 00 6b 00 65 00 79 00 2e 00 63 00 6f 00 2e 00 6b 00 72 00 } //01 00  click.adkey.co.kr
		$a_01_3 = {68 61 6e 2d 6b 65 79 2e 63 6f 6d } //01 00  han-key.com
		$a_01_4 = {73 00 68 00 6f 00 70 00 70 00 69 00 6e 00 67 00 2e 00 64 00 61 00 75 00 6d 00 2e 00 6e 00 65 00 74 00 } //01 00  shopping.daum.net
		$a_01_5 = {67 00 6d 00 61 00 72 00 6b 00 65 00 74 00 2e 00 63 00 6f 00 2e 00 6b 00 72 00 } //01 00  gmarket.co.kr
		$a_01_6 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 54 00 6f 00 6f 00 6c 00 62 00 61 00 72 00 } //01 00  Software\Microsoft\Internet Explorer\Toolbar
		$a_01_7 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 20 00 48 00 65 00 6c 00 70 00 65 00 72 00 20 00 4f 00 62 00 6a 00 65 00 63 00 74 00 73 00 } //01 00  Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
		$a_01_8 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_9 = {49 6e 74 65 72 6e 65 74 43 6c 6f 73 65 48 61 6e 64 6c 65 } //01 00  InternetCloseHandle
		$a_01_10 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //00 00  InternetReadFile
	condition:
		any of ($a_*)
 
}