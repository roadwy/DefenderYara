
rule Backdoor_Win64_Mozaakai_MAK_MTB{
	meta:
		description = "Backdoor:Win64/Mozaakai.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 c6 b9 [0-04] 2b c8 b8 [0-04] 8d 3c [0-01] c1 e7 [0-01] f7 ef 03 d7 c1 fa [0-01] 8b c2 c1 e8 [0-01] 03 d0 6b c2 [0-01] 2b f8 b8 90 1b 01 83 c7 90 1b 06 f7 ef 03 d7 c1 fa [0-01] 8b c2 c1 e8 90 1b 05 03 d0 6b c2 90 1b 06 2b f8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}