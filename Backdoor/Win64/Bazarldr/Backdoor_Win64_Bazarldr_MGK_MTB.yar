
rule Backdoor_Win64_Bazarldr_MGK_MTB{
	meta:
		description = "Backdoor:Win64/Bazarldr.MGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 11 b8 [0-04] 2b c2 44 6b c0 [0-01] 41 8b c3 41 f7 e8 41 03 d0 c1 fa [0-01] 8b c2 c1 e8 [0-01] 03 d0 6b c2 [0-01] 44 2b c0 41 8b c3 41 83 c0 90 1b 04 41 f7 e8 41 03 d0 c1 fa 90 1b 02 8b c2 c1 e8 90 1b 03 03 d0 6b c2 90 1b 04 44 2b c0 45 88 01 49 ff c1 49 83 ea 01 75 } //1
		$a_03_1 = {41 0f b6 11 b8 [0-04] 2b c2 44 8d 04 c0 41 8b c3 41 c1 e0 [0-01] 41 f7 e8 41 03 d0 c1 fa [0-01] 8b c2 c1 e8 [0-01] 03 d0 6b c2 [0-01] 44 2b c0 41 8b c3 41 83 c0 90 1b 04 41 f7 e8 41 03 d0 c1 fa 90 1b 02 8b c2 c1 e8 90 1b 03 03 d0 6b c2 90 1b 04 44 2b c0 45 88 01 49 ff c1 49 83 ea 01 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}