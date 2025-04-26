
rule Backdoor_Win64_Mozaakai_MK_MTB{
	meta:
		description = "Backdoor:Win64/Mozaakai.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 05 07 19 00 00 89 c1 80 f1 [0-01] 20 c1 89 c8 b2 [0-01] 20 d0 30 d1 08 c1 88 0d f0 [0-03] b8 [0-04] 45 31 ed e9 } //1
		$a_03_1 = {8b 4c 84 48 89 ca f7 d2 81 e2 [0-04] 81 e1 [0-04] 09 d1 81 f1 [0-04] 89 [0-03] 48 85 c0 b8 [0-02] 00 00 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Backdoor_Win64_Mozaakai_MK_MTB_2{
	meta:
		description = "Backdoor:Win64/Mozaakai.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 83 f8 [0-01] 74 [0-01] 8b 44 24 [0-01] 39 05 1b 97 02 00 90 18 8b 0d [0-04] 48 8b 44 24 [0-01] c6 04 08 [0-01] c7 44 24 [0-03] 00 00 e8 [0-04] c7 44 24 [0-03] 00 00 8b 05 [0-04] 83 c0 01 89 05 [0-04] eb } //1
		$a_03_1 = {8b 05 e6 d7 [0-02] 8b 0d f0 d7 90 1b 00 33 c8 48 8b 05 3b d8 90 1b 00 89 08 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Backdoor_Win64_Mozaakai_MK_MTB_3{
	meta:
		description = "Backdoor:Win64/Mozaakai.MK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 02 48 8d 52 ff 42 88 44 31 0c 48 ff c1 48 3b cb 7c ec } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Backdoor_Win64_Mozaakai_MK_MTB_4{
	meta:
		description = "Backdoor:Win64/Mozaakai.MK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0a 48 8d 52 ff 42 88 4c 30 0c 48 ff c0 48 3b c7 7c ec } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}