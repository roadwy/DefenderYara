
rule Trojan_BAT_AgentTesla_HN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_81_0 = {45 6e 63 72 79 70 74 } //01 00  Encrypt
		$a_81_1 = {41 6e 74 69 53 61 6e 64 62 6f 78 69 65 } //01 00  AntiSandboxie
		$a_81_2 = {41 6e 74 69 57 69 72 65 73 68 61 72 6b } //01 00  AntiWireshark
		$a_81_3 = {41 6e 74 69 50 72 6f 63 65 73 73 4d 6f 6e 69 74 6f 72 } //01 00  AntiProcessMonitor
		$a_81_4 = {41 6e 74 69 45 6d 75 6c 61 74 6f 72 } //01 00  AntiEmulator
		$a_81_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_81_6 = {64 72 6f 70 4c 6f 63 61 74 69 6f 6e } //01 00  dropLocation
		$a_81_7 = {48 69 64 64 65 6e } //01 00  Hidden
		$a_81_8 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //01 00  HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_81_9 = {63 6f 6d 6d 61 6e 64 4c 69 6e 65 } //01 00  commandLine
		$a_81_10 = {72 75 6e 61 73 } //00 00  runas
	condition:
		any of ($a_*)
 
}