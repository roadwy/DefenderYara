
rule Backdoor_Win64_Supper_CM_MTB{
	meta:
		description = "Backdoor:Win64/Supper.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 39 d1 49 0f 44 c9 48 0f b6 01 30 02 48 83 c2 01 48 83 c1 01 4c 39 c2 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}