
rule Backdoor_Win64_Havoc_B_MTB{
	meta:
		description = "Backdoor:Win64/Havoc.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 01 c0 83 c2 ?? 0f b6 00 30 01 48 83 c1 ?? 49 39 c9 } //2
		$a_03_1 = {4c 89 c0 ba ?? ?? ?? ?? 0f b6 00 30 01 48 83 c1 ?? 49 39 c9 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}