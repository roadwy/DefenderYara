
rule Trojan_Win64_BazaarLoader_CCGG_MTB{
	meta:
		description = "Trojan:Win64/BazaarLoader.CCGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 41 6c 72 65 61 64 79 45 78 69 73 74 } //01 00  Global\AlreadyExist
		$a_01_1 = {6f 73 5f 76 65 72 73 69 6f 6e 22 3a 22 25 73 } //01 00  os_version":"%s
		$a_01_2 = {77 69 6e 5f 69 64 22 3a 22 25 73 } //01 00  win_id":"%s
		$a_01_3 = {63 6c 69 65 6e 74 5f 76 65 72 73 69 6f 6e 22 3a 25 66 } //01 00  client_version":%f
		$a_01_4 = {74 61 73 6b 5f 69 64 } //01 00  task_id
		$a_01_5 = {53 79 73 74 65 6d 5c 78 78 78 31 2e 62 61 6b } //01 00  System\xxx1.bak
		$a_01_6 = {41 00 64 00 64 00 2d 00 4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 45 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 50 00 61 00 74 00 68 00 20 00 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 } //00 00  Add-MpPreference -ExclusionPath c:\windows
	condition:
		any of ($a_*)
 
}