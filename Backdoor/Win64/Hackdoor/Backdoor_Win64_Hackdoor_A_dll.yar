
rule Backdoor_Win64_Hackdoor_A_dll{
	meta:
		description = "Backdoor:Win64/Hackdoor.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 09 00 00 01 00 "
		
	strings :
		$a_80_0 = {54 68 65 20 76 65 72 73 69 6f 6e 20 6f 66 20 70 65 72 73 6f 6e 61 6c 20 68 61 63 6b 65 72 27 73 20 64 6f 6f 72 20 73 65 72 76 65 72 20 69 73 } //The version of personal hacker's door server is  01 00 
		$a_80_1 = {49 27 6d 68 61 63 6b 65 72 79 79 74 68 61 63 31 39 37 37 } //I'mhackeryythac1977  01 00 
		$a_01_2 = {47 6c 6f 62 61 6c 5c 64 6f 6f 72 6e 65 65 64 73 68 75 74 00 } //01 00  汇扯污摜潯湲敥獤畨t
		$a_01_3 = {68 6b 64 6f 6f 72 65 76 74 00 } //01 00  歨潤牯癥t
		$a_01_4 = {53 65 6c 6c 5f 44 45 53 4b 54 4f 50 00 } //01 00 
		$a_01_5 = {25 73 25 64 2e 25 64 20 53 45 51 3a 25 73 0d 0a 25 73 0d 0a 00 } //01 00 
		$a_01_6 = {44 6f 6d 61 69 6e 3a 25 53 2c 55 73 65 72 3a 25 53 2c 50 61 73 73 77 6f 72 64 3a 25 73 00 } //01 00  潄慭湩┺ⱓ獕牥┺ⱓ慐獳潷摲┺s
		$a_01_7 = {70 72 65 61 70 72 65 20 74 6f 20 6c 6f 61 64 20 64 72 69 76 65 72 21 21 21 20 72 65 74 43 6f 64 65 3d 25 64 00 } //01 00 
		$a_01_8 = {48 b8 75 6e 6b 6e 6f 77 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win64_Hackdoor_A_dll_2{
	meta:
		description = "Backdoor:Win64/Hackdoor.A!dll,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 44 6f 73 44 65 76 69 63 65 73 5c 6b 69 66 65 73 } //01 00  \DosDevices\kifes
		$a_01_1 = {5c 44 65 76 69 63 65 5c 6b 69 66 65 73 } //01 00  \Device\kifes
		$a_01_2 = {68 65 6c 6c 6f 68 61 68 61 } //01 00  hellohaha
		$a_01_3 = {69 70 66 6c 74 64 72 76 2e 73 79 73 } //01 00  ipfltdrv.sys
		$a_01_4 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 49 00 50 00 46 00 49 00 4c 00 54 00 45 00 52 00 44 00 52 00 49 00 56 00 45 00 52 00 } //00 00  \Device\IPFILTERDRIVER
	condition:
		any of ($a_*)
 
}