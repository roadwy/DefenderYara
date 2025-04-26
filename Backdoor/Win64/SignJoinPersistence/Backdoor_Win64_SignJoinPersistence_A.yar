
rule Backdoor_Win64_SignJoinPersistence_A{
	meta:
		description = "Backdoor:Win64/SignJoinPersistence.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4f 6e 65 44 72 69 76 65 53 72 76 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}