
rule Trojan_Win32_Agent_BM{
	meta:
		description = "Trojan:Win32/Agent.BM,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //01 00  SeShutdownPrivilege
		$a_00_1 = {75 6e 70 61 63 6b 65 64 5c } //01 00  unpacked\
		$a_00_2 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 00 00 ff ff ff ff 04 00 00 00 4d 59 49 44 } //01 00 
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 48 6f 73 74 } //01 00  Software\Microsoft\Windows NT\CurrentVersion\SvcHost
		$a_00_4 = {73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //01 00  svchost.exe -k netsvcs
		$a_00_5 = {52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f } //01 00  Referer: http://
		$a_01_6 = {63 61 70 43 72 65 61 74 65 43 61 70 74 75 72 65 57 69 6e 64 6f 77 41 } //00 00  capCreateCaptureWindowA
	condition:
		any of ($a_*)
 
}