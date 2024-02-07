
rule Trojan_BAT_MetaSploit_A_MTB{
	meta:
		description = "Trojan:BAT/MetaSploit.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 00 6b 00 6a 00 66 00 6b 00 6c 00 73 00 64 00 68 00 6c 00 6a 00 6b 00 66 00 68 00 67 00 6a 00 6c 00 6b 00 61 00 73 00 64 00 66 00 68 00 67 00 6a 00 73 00 6b 00 64 00 66 00 68 00 67 00 6a 00 6b 00 73 00 64 00 66 00 68 00 67 00 6a 00 6a 00 } //02 00  skjfklsdhljkfhgjlkasdfhgjskdfhgjksdfhgjj
		$a_01_1 = {73 00 61 00 6b 00 67 00 64 00 68 00 66 00 61 00 73 00 67 00 66 00 64 00 6b 00 68 00 6a 00 61 00 73 00 64 00 67 00 66 00 68 00 61 00 6a 00 73 00 67 00 64 00 66 00 68 00 6a 00 61 00 73 00 67 00 64 00 76 00 68 00 6a 00 78 00 7a 00 63 00 67 00 76 00 62 00 68 00 6a 00 62 00 65 00 68 00 61 00 75 00 66 00 67 00 61 00 68 00 6a 00 73 00 64 00 66 00 67 00 76 00 63 00 68 00 6a 00 63 00 78 00 62 00 76 00 } //02 00  sakgdhfasgfdkhjasdgfhajsgdfhjasgdvhjxzcgvbhjbehaufgahjsdfgvchjcxbv
		$a_01_2 = {44 00 46 00 4c 00 47 00 4a 00 44 00 46 00 4c 00 47 00 42 00 4a 00 4e 00 44 00 46 00 4c 00 4e 00 42 00 4c 00 44 00 46 00 4e 00 53 00 4b 00 46 00 47 00 42 00 4e 00 4d 00 53 00 4c 00 44 00 46 00 42 00 } //01 00  DFLGJDFLGBJNDFLNBLDFNSKFGBNMSLDFB
		$a_01_3 = {43 72 65 61 74 65 54 68 72 65 61 64 } //01 00  CreateThread
		$a_01_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //01 00  WaitForSingleObject
		$a_01_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}