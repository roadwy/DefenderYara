
rule Backdoor_Win64_ProjectB_A{
	meta:
		description = "Backdoor:Win64/ProjectB.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 6f 74 4e 65 74 2e 64 6c 6c 00 44 65 66 61 75 6c 74 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}