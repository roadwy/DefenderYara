
rule Backdoor_Win64_Bazarldr_MAK_MTB{
	meta:
		description = "Backdoor:Win64/Bazarldr.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f be c0 48 ff c1 03 d0 69 d2 [0-02] 00 00 8b c2 c1 f8 [0-01] 33 d0 8a 01 84 c0 75 } //1
		$a_03_1 = {8d 0c d2 8b c1 c1 f8 [0-01] 33 c1 69 c0 [0-02] 00 00 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Backdoor_Win64_Bazarldr_MAK_MTB_2{
	meta:
		description = "Backdoor:Win64/Bazarldr.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a c1 02 85 [0-04] 30 84 0d [0-04] 48 03 cf 48 83 f9 [0-01] 72 } //1
		$a_03_1 = {02 c8 30 4c 04 [0-01] 49 03 c6 48 83 f8 [0-01] 73 06 8a 4c 24 [0-01] eb } //1
		$a_03_2 = {8a 44 24 20 02 c1 30 44 0c [0-01] 49 03 ce 48 83 f9 [0-01] 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}