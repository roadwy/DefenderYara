
rule Trojan_Win64_Baryas_MBXS_MTB{
	meta:
		description = "Trojan:Win64/Baryas.MBXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 2e 64 6c 6c 00 44 6c 6c 4c 6f 61 64 00 44 6c 6c 4c 6f 61 64 58 00 50 32 50 4d 61 69 6e 53 74 61 72 74 00 50 32 50 4e 65 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}