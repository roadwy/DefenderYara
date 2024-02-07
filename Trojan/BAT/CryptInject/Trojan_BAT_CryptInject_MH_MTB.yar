
rule Trojan_BAT_CryptInject_MH_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 16 13 04 2b 2a 00 07 11 04 9a 6f 90 01 03 0a 03 28 90 01 03 0a 13 05 11 05 2c 0d 00 07 11 04 9a 6f 90 01 03 0a 0a 2b 14 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 06 11 06 2d c9 90 00 } //01 00 
		$a_01_1 = {45 00 61 00 73 00 79 00 58 00 70 00 6c 00 6f 00 69 00 74 00 73 00 20 00 41 00 50 00 49 00 } //01 00  EasyXploits API
		$a_01_2 = {69 00 73 00 20 00 69 00 6e 00 6a 00 65 00 63 00 74 00 69 00 6e 00 67 00 } //01 00  is injecting
		$a_01_3 = {64 6f 53 68 69 74 } //01 00  doShit
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00  DownloadString
		$a_01_5 = {44 00 69 00 64 00 20 00 74 00 68 00 65 00 20 00 64 00 6c 00 6c 00 20 00 70 00 72 00 6f 00 70 00 65 00 72 00 6c 00 79 00 20 00 69 00 6e 00 6a 00 65 00 63 00 74 00 3f 00 } //01 00  Did the dll properly inject?
		$a_01_6 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_8 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //00 00  CreateRemoteThread
	condition:
		any of ($a_*)
 
}