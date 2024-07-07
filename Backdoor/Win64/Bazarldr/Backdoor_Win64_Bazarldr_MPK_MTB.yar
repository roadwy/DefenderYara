
rule Backdoor_Win64_Bazarldr_MPK_MTB{
	meta:
		description = "Backdoor:Win64/Bazarldr.MPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 0a b8 90 02 04 83 e9 90 02 01 44 6b c1 90 02 01 41 f7 e8 41 03 d0 c1 fa 90 02 01 8b c2 c1 e8 90 02 01 03 d0 6b c2 90 02 01 44 2b c0 b8 90 1b 00 41 83 c0 90 1b 05 41 f7 e8 41 03 d0 c1 fa 90 1b 03 8b c2 c1 e8 90 1b 04 03 d0 6b c2 90 1b 05 44 2b c0 45 88 02 49 ff c2 49 83 eb 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}