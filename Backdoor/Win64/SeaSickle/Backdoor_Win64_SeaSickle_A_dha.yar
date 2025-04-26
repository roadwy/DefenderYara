
rule Backdoor_Win64_SeaSickle_A_dha{
	meta:
		description = "Backdoor:Win64/SeaSickle.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_42_0 = {8d 48 02 f7 e9 41 8b c8 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 32 2b c8 8d 41 02 42 0f b6 4c 13 01 48 98 42 2a 0c 18 b8 90 01 04 41 88 4a 01 90 00 00 } //1
	condition:
		((#a_42_0  & 1)*1) >=1
 
}