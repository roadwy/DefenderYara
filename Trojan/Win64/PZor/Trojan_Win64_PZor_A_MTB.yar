
rule Trojan_Win64_PZor_A_MTB{
	meta:
		description = "Trojan:Win64/PZor.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 ea 4c 01 e2 4d 89 fa 49 c1 ea ?? 4d 89 f3 49 c1 eb 10 49 b8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}