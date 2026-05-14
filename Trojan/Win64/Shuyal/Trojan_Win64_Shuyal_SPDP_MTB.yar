
rule Trojan_Win64_Shuyal_SPDP_MTB{
	meta:
		description = "Trojan:Win64/Shuyal.SPDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 44 24 20 30 44 0c 21 0f b6 44 24 20 30 44 0c 22 0f b6 44 24 20 30 44 0c 23 0f b6 44 24 20 30 44 0c 24 0f b6 44 24 20 30 44 0c 25 0f b6 44 24 20 30 44 0c 26 0f b6 44 24 20 30 44 0c 27 0f b6 44 24 20 30 44 0c 28 0f b6 44 24 20 30 44 0d 80 0f b6 44 24 20 30 44 0d 81 0f b6 44 24 20 30 44 0d 82 0f b6 44 24 20 30 44 0d 83 0f b6 44 24 20 30 44 0d 84 0f b6 44 24 20 30 44 0d 85 0f b6 44 24 20 30 44 0d 86 0f b6 44 24 20 30 44 0d 87 48 83 c1 10 48 83 f9 50 0f 82 } //5
		$a_01_1 = {0f b6 45 b7 30 44 0d b8 0f b6 45 b7 30 44 0d b9 48 83 c1 02 48 83 f9 3a 72 } //4
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}