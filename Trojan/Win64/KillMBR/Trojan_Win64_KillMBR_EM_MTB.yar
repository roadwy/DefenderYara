
rule Trojan_Win64_KillMBR_EM_MTB{
	meta:
		description = "Trojan:Win64/KillMBR.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 6b 69 6c 6c 77 69 6e 64 6f 77 73 } //01 00  /killwindows
		$a_01_1 = {2f 4b 69 6c 6c 48 61 72 64 44 69 73 6b } //01 00  /KillHardDisk
		$a_01_2 = {2f 6b 69 6c 6c 4d 42 52 } //01 00  /killMBR
		$a_01_3 = {2f 61 75 74 6f 75 70 } //01 00  /autoup
		$a_01_4 = {53 75 70 65 72 2d 56 69 72 75 73 } //01 00  Super-Virus
		$a_01_5 = {43 61 63 6c 73 20 43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 74 61 73 6b 6d 67 72 2e 65 78 65 20 2f 74 20 2f 65 20 2f 63 20 2f 67 } //01 00  Cacls C:\windows\system32\taskmgr.exe /t /e /c /g
		$a_01_6 = {49 20 61 6d 20 76 69 72 75 73 21 20 46 75 63 6b 20 79 6f 75 } //00 00  I am virus! Fuck you
	condition:
		any of ($a_*)
 
}