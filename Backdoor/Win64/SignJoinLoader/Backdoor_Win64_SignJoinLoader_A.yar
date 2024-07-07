
rule Backdoor_Win64_SignJoinLoader_A{
	meta:
		description = "Backdoor:Win64/SignJoinLoader.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4f 44 53 65 63 75 72 69 74 79 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 6d 73 78 6d 6c 33 2e 64 6c 6c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}