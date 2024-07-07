
rule Trojan_Win64_CobaltStrike_CB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c3 31 c0 39 c6 7e 90 01 01 48 89 c2 83 e2 90 01 01 8a 54 15 90 01 01 32 14 07 88 14 03 48 ff c0 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_CB_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c8 8b 43 90 01 01 31 8b 90 01 04 8b 8b 90 01 04 2b 4b 90 01 01 81 f1 90 01 04 0f af c1 48 8b 8b 90 01 04 89 43 90 01 01 8b 43 90 01 01 31 04 11 48 83 c2 90 01 01 8b 83 90 01 04 01 43 90 01 01 48 81 fa 90 01 04 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_CB_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 79 54 65 73 74 4d 75 74 65 78 31 } //1 MyTestMutex1
		$a_01_1 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //1 CreateMutexA
		$a_01_2 = {6f 31 75 68 62 32 62 55 46 57 71 48 54 55 52 6e 46 53 48 72 47 73 6e } //1 o1uhb2bUFWqHTURnFSHrGsn
		$a_01_3 = {4f 70 65 6e 4d 75 74 65 78 41 } //1 OpenMutexA
		$a_01_4 = {4b 53 50 4b 55 70 77 52 39 4e 67 31 68 75 72 6e 6b 59 70 39 42 49 68 48 58 32 52 75 62 6a 74 6a } //1 KSPKUpwR9Ng1hurnkYp9BIhHX2Rubjtj
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}