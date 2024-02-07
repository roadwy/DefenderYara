
rule Trojan_Linux_KillFile_A_xp{
	meta:
		description = "Trojan:Linux/KillFile.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {4b 69 6c 6c 50 72 6f 63 65 73 73 } //01 00  KillProcess
		$a_00_1 = {74 63 70 5f 63 6f 6e 6e 65 63 74 5f 6e 62 6c 6f 63 6b } //01 00  tcp_connect_nblock
		$a_00_2 = {52 75 6e 46 69 6c 65 } //01 00  RunFile
		$a_00_3 = {61 62 73 74 72 61 63 74 5f 75 72 6c } //01 00  abstract_url
		$a_00_4 = {53 68 65 6c 6c 45 65 78 65 63 } //01 00  ShellEexec
		$a_00_5 = {68 74 74 70 5f 64 6f 77 6e 6c 6f 61 64 } //01 00  http_download
		$a_00_6 = {6b 69 6c 6c 66 69 6c 65 61 6e 64 70 69 64 } //00 00  killfileandpid
	condition:
		any of ($a_*)
 
}