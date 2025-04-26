
rule Backdoor_Win64_Mozaakai_ZY_MTB{
	meta:
		description = "Backdoor:Win64/Mozaakai.ZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8a 00 48 83 c2 01 49 83 e8 01 48 3b d7 88 44 32 [0-01] 7c ec } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}