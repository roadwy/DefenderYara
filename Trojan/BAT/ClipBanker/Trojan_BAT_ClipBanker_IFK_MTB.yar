
rule Trojan_BAT_ClipBanker_IFK_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.IFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {77 59 74 74 55 4b 7a 46 43 70 59 68 54 66 71 48 77 52 63 4c 76 4c 67 6b 4a 55 4a 65 41 31 } //01 00  wYttUKzFCpYhTfqHwRcLvLgkJUJeA1
		$a_81_1 = {59 61 59 70 78 6d 57 75 68 64 4e 75 73 67 54 69 79 56 67 73 4b 4e 53 56 7a 78 69 6a } //01 00  YaYpxmWuhdNusgTiyVgsKNSVzxij
		$a_81_2 = {66 74 53 4a 5a 4a 65 72 45 6d 4c 55 77 58 47 70 66 42 69 45 46 71 62 6b 66 68 6d 69 39 } //01 00  ftSJZJerEmLUwXGpfBiEFqbkfhmi9
		$a_81_3 = {5a 70 6c 43 57 72 55 5a 51 49 56 6d 55 64 63 62 4e 7a 6a 4c 49 70 56 42 64 4c 4b 44 4a } //01 00  ZplCWrUZQIVmUdcbNzjLIpVBdLKDJ
		$a_81_4 = {63 6e 43 6b 55 65 4e 70 4c 56 52 50 6f 42 41 6f 41 48 64 54 43 6a 6f 44 59 6b 4a 7a } //01 00  cnCkUeNpLVRPoBAoAHdTCjoDYkJz
		$a_01_5 = {6a 00 6b 00 61 00 65 00 69 00 64 00 6f 00 33 00 30 00 2e 00 65 00 78 00 65 00 } //00 00  jkaeido30.exe
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_ClipBanker_IFK_MTB_2{
	meta:
		description = "Trojan:BAT/ClipBanker.IFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 00 55 00 54 00 50 00 55 00 54 00 2d 00 4f 00 4e 00 4c 00 49 00 4e 00 45 00 50 00 4e 00 47 00 54 00 4f 00 4f 00 4c 00 53 00 } //01 00  OUTPUT-ONLINEPNGTOOLS
		$a_01_1 = {75 00 66 00 61 00 69 00 6f 00 66 00 77 00 71 00 2e 00 65 00 78 00 65 00 } //01 00  ufaiofwq.exe
		$a_81_2 = {44 69 73 63 6f 72 64 20 4c 69 6e 6b 20 3a 20 20 76 31 2e 30 2e 30 2d 63 75 73 74 6f 6d } //01 00  Discord Link :  v1.0.0-custom
		$a_81_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //01 00  ShellExecute
		$a_81_4 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_81_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_6 = {73 65 74 5f 55 73 65 72 41 67 65 6e 74 } //01 00  set_UserAgent
		$a_81_7 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //00 00  DownloadData
	condition:
		any of ($a_*)
 
}