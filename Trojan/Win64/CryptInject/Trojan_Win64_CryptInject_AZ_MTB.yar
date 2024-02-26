
rule Trojan_Win64_CryptInject_AZ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 73 6f 6d 65 5c 66 69 6c 65 2e 64 6f 74 2e 74 78 74 } //01 00  c:\some\file.dot.txt
		$a_01_1 = {77 69 6e 64 6f 77 73 5f 37 5f 77 69 6e 64 6f 77 73 5f 31 30 5f 63 68 65 63 6b 5f 72 75 6e 6e 69 6e 67 5f 6f 6e 63 65 5f 6d 75 74 65 78 } //01 00  windows_7_windows_10_check_running_once_mutex
		$a_01_2 = {63 3a 5c 6d 73 66 5c 33 5c 68 74 74 70 2e 64 6c 6c } //01 00  c:\msf\3\http.dll
		$a_01_3 = {50 72 6f 63 65 73 73 55 74 69 6c 73 3a 3a 49 73 55 73 65 72 41 64 6d 69 6e 28 29 } //01 00  ProcessUtils::IsUserAdmin()
		$a_01_4 = {57 61 69 74 20 75 6e 74 69 6c 20 47 65 74 44 6f 6d 61 69 6e 41 6e 64 50 63 28 29 } //01 00  Wait until GetDomainAndPc()
		$a_01_5 = {42 00 6f 00 74 00 49 00 6e 00 66 00 6f 00 2e 00 74 00 78 00 74 00 } //01 00  BotInfo.txt
		$a_01_6 = {25 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 25 00 5c 00 6c 00 6f 00 67 00 2e 00 6c 00 6f 00 67 00 } //01 00  %programdata%\log.log
		$a_01_7 = {25 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 25 00 5c 00 73 00 73 00 68 00 2e 00 64 00 6c 00 6c 00 } //00 00  %programdata%\ssh.dll
	condition:
		any of ($a_*)
 
}