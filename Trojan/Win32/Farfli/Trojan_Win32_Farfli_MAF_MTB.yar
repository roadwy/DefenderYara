
rule Trojan_Win32_Farfli_MAF_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {b2 67 b0 65 88 54 24 1a 88 54 24 22 88 44 24 15 88 44 24 17 88 44 24 21 88 44 24 23 8d 54 24 08 8d 44 24 14 52 b1 69 50 6a 00 c6 44 24 20 53 c6 44 24 22 44 } //01 00 
		$a_01_1 = {57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 42 52 65 6d 6f 74 65 73 2e 65 78 65 } //01 00  WINDOWS\system32\BRemotes.exe
		$a_01_2 = {75 73 65 72 2e 71 7a 6f 6e 65 2e 71 71 2e 63 6f 6d } //01 00  user.qzone.qq.com
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 20 42 41 54 43 4f 4d } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v BATCOM
		$a_01_4 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_01_5 = {4c 6f 63 6b 53 65 72 76 69 63 65 44 61 74 61 62 61 73 65 } //00 00  LockServiceDatabase
	condition:
		any of ($a_*)
 
}