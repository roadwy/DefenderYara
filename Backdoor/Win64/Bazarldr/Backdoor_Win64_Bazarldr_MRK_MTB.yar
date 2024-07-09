
rule Backdoor_Win64_Bazarldr_MRK_MTB{
	meta:
		description = "Backdoor:Win64/Bazarldr.MRK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 c1 e9 20 01 d1 83 c1 [0-01] 89 ce c1 ee [0-01] c1 f9 06 01 f1 89 ce c1 e6 07 29 f1 01 d1 83 c1 90 1b 00 88 4c 04 [0-01] 48 ff c0 48 83 f8 [0-01] 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}