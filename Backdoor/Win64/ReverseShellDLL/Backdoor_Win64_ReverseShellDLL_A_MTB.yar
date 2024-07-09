
rule Backdoor_Win64_ReverseShellDLL_A_MTB{
	meta:
		description = "Backdoor:Win64/ReverseShellDLL.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f 57 c0 45 33 c9 0f 11 45 b0 48 89 45 b0 45 33 c0 48 8b 45 d8 33 c9 48 89 45 b8 48 89 45 c0 48 8d ?? ?? 48 89 44 24 48 48 8d ?? ?? ?? 48 89 44 24 40 4c 89 7c 24 38 4c 89 7c 24 30 0f 11 44 24 60 44 89 7c 24 28 0f 11 45 ?? c7 44 24 20 01 00 00 00 0f 11 44 24 70 c7 44 24 60 68 00 00 00 0f 11 45 80 c7 45 9c 01 01 00 00 0f 11 45 a0 ff 15 } //1
		$a_03_1 = {48 8b 4c 24 50 48 8d ?? ?? 4c 89 7c 24 28 45 33 c9 45 33 c0 48 89 44 24 20 33 d2 ff 15 } //1
		$a_01_2 = {45 58 49 54 53 48 45 4c 4c 0d 0a 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}