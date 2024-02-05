
rule Trojan_Win32_KeyLogger_RFS_MTB{
	meta:
		description = "Trojan:Win32/KeyLogger.RFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_81_0 = {74 65 6d 70 7b 25 6c 75 7d 2e 74 6d 70 } //01 00 
		$a_81_1 = {74 65 6d 70 7b 44 45 33 42 38 44 45 32 33 36 42 44 7d 2e 74 6d 70 } //01 00 
		$a_81_2 = {74 65 6d 70 25 64 2e 7a 69 70 } //01 00 
		$a_00_3 = {43 6f 64 65 73 5c 4d 41 49 4f 5c 4d 41 49 4f 5c 4d 41 49 4f 2d 76 33 5c 52 65 6c 65 61 73 65 5c 4d 41 49 4f 2e 70 64 62 } //01 00 
		$a_81_4 = {5b 43 74 72 6c 52 5d } //01 00 
		$a_81_5 = {5b 57 69 6e 52 5d } //01 00 
		$a_81_6 = {5b 56 6f 6c 44 5d } //01 00 
		$a_81_7 = {5b 45 78 65 63 5d } //01 00 
		$a_81_8 = {5b 45 73 63 5d } //01 00 
		$a_81_9 = {5b 4e 75 6d 4c 6f 63 6b 5d } //01 00 
		$a_81_10 = {5b 41 72 72 6f 77 4c 5d } //00 00 
	condition:
		any of ($a_*)
 
}