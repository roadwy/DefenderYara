
rule Backdoor_Win64_Bladabindi_PGC_MTB{
	meta:
		description = "Backdoor:Win64/Bladabindi.PGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {f3 42 0f 6f 44 00 e0 48 8d 40 40 83 c2 40 66 0f 6f ca 0f 57 c2 f3 0f 7f 40 a0 f3 0f 6f 44 01 a0 0f 57 c2 f3 0f 7f 40 b0 f3 42 0f 6f 44 00 c0 0f 57 c8 f3 0f 6f 44 01 c0 f3 0f 7f 48 c0 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}