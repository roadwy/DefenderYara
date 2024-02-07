
rule Trojan_Win32_Remcos_MTB{
	meta:
		description = "Trojan:Win32/Remcos!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {52 65 6d 63 6f 73 } //03 00  Remcos
		$a_01_1 = {45 72 72 6f 72 3a 20 55 6e 61 62 6c 65 20 74 6f 20 63 72 65 61 74 65 20 73 6f 63 6b 65 74 } //05 00  Error: Unable to create socket
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c } //05 00  Software\Microsoft\Windows\CurrentVersion\Uninstall
		$a_01_3 = {54 4c 53 31 33 2d 41 45 53 31 32 38 2d 47 43 4d 2d 53 48 41 32 35 36 } //02 00  TLS13-AES128-GCM-SHA256
		$a_01_4 = {73 74 61 74 75 73 20 61 75 64 69 6f 20 6d 6f 64 65 } //01 00  status audio mode
		$a_01_5 = {63 6f 6e 6e 65 63 74 69 6f 6e 20 72 65 73 65 74 } //01 00  connection reset
		$a_01_6 = {4d 75 74 65 78 5f 52 65 6d 57 61 74 63 68 64 6f 67 } //01 00  Mutex_RemWatchdog
		$a_01_7 = {53 48 44 65 6c 65 74 65 4b 65 79 57 } //00 00  SHDeleteKeyW
	condition:
		any of ($a_*)
 
}