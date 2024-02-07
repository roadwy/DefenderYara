
rule Backdoor_Win32_Hido_gen_A{
	meta:
		description = "Backdoor:Win32/Hido.gen!A,SIGNATURE_TYPE_PEHSTR,14 00 14 00 0b 00 00 02 00 "
		
	strings :
		$a_01_0 = {70 72 6f 74 65 63 74 6f 72 73 65 72 76 69 63 65 } //02 00  protectorservice
		$a_01_1 = {70 72 6f 74 65 63 74 6f 72 2e 73 79 73 } //02 00  protector.sys
		$a_01_2 = {4e 74 43 72 65 61 74 65 53 65 63 74 69 6f 6e } //02 00  NtCreateSection
		$a_01_3 = {5c 5c 2e 5c 50 52 4f 54 45 43 54 4f 52 } //02 00  \\.\PROTECTOR
		$a_01_4 = {57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 72 65 67 73 76 72 33 32 2e 65 78 65 } //02 00  WINDOWS\system32\regsvr32.exe
		$a_01_5 = {57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 73 63 2e 65 78 65 } //02 00  WINDOWS\system32\sc.exe
		$a_01_6 = {65 61 73 79 63 6c 69 63 6b 70 6c 75 73 39 } //02 00  easyclickplus9
		$a_01_7 = {45 78 70 6c 6f 72 65 72 5f 54 72 69 64 65 6e 74 44 6c 67 46 72 61 6d 65 } //02 00  Explorer_TridentDlgFrame
		$a_01_8 = {43 57 65 62 42 72 6f 77 73 65 72 32 } //02 00  CWebBrowser2
		$a_01_9 = {36 30 2e 31 39 30 2e 32 32 33 2e 31 31 } //02 00  60.190.223.11
		$a_01_10 = {32 31 39 2e 32 33 32 2e 32 32 34 2e 31 32 36 } //00 00  219.232.224.126
	condition:
		any of ($a_*)
 
}