
rule Backdoor_Win64_Havoc_C_MTB{
	meta:
		description = "Backdoor:Win64/Havoc.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 d0 83 c0 90 01 01 4c 01 c2 0f b6 12 30 11 48 83 c1 90 00 } //2
		$a_03_1 = {4c 89 c2 b8 90 01 04 0f b6 12 30 11 48 83 c1 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}