
rule Trojan_Win32_VB_ES{
	meta:
		description = "Trojan:Win32/VB.ES,SIGNATURE_TYPE_PEHSTR,33 00 33 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //0a 00  MSVBVM60.DLL
		$a_01_1 = {49 63 6d 70 43 72 65 61 74 65 46 69 6c 65 } //0a 00  IcmpCreateFile
		$a_01_2 = {47 00 45 00 54 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //0a 00  GET http://
		$a_01_3 = {5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //0a 00  \Project1.vbp
		$a_01_4 = {5c 00 77 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //01 00  \winlogon.exe
		$a_01_5 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //01 00  Install.exe
		$a_01_6 = {41 00 74 00 74 00 61 00 63 00 6b 00 73 00 20 00 45 00 6e 00 61 00 62 00 6c 00 65 00 64 00 } //00 00  Attacks Enabled
	condition:
		any of ($a_*)
 
}