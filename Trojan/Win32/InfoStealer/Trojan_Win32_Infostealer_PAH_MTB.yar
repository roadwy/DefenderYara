
rule Trojan_Win32_Infostealer_PAH_MTB{
	meta:
		description = "Trojan:Win32/Infostealer.PAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run\
		$a_01_1 = {4d 79 20 73 61 76 65 64 20 70 61 73 73 77 6f 72 64 73 20 2d 20 4e 6f 74 65 70 61 64 } //01 00  My saved passwords - Notepad
		$a_01_2 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 } //01 00  Internet Explorer_Server
		$a_01_3 = {42 61 6e 6b 20 6f 66 20 41 6d 65 72 69 63 61 20 6c 6f 67 2d 69 6e } //01 00  Bank of America log-in
		$a_01_4 = {43 69 74 79 42 61 6e 6b 20 6c 6f 67 2d 69 6e } //01 00  CityBank log-in
		$a_01_5 = {41 3a 5c 7c 7c 7c 7c 7c 7c 7c 7c 7c 7c 7c 7c 2e 73 77 66 } //01 00  A:\||||||||||||.swf
		$a_01_6 = {59 61 68 6f 6f 21 20 4d 65 73 73 65 6e 67 65 72 } //01 00  Yahoo! Messenger
		$a_01_7 = {74 6f 6f 6c 74 69 70 73 5f 63 6c 61 73 73 33 32 } //01 00  tooltips_class32
		$a_01_8 = {61 6e 74 69 76 69 72 75 73 2e 65 78 65 } //01 00  antivirus.exe
		$a_01_9 = {70 74 5f 6c 6f 67 69 6e 5f 73 69 67 3d } //01 00  pt_login_sig=
		$a_01_10 = {77 69 6e 6c 6f 67 6f 6e 2e 65 78 65 } //00 00  winlogon.exe
	condition:
		any of ($a_*)
 
}