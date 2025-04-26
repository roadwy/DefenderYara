
rule Trojan_Win64_Zusy_ARA_MTB{
	meta:
		description = "Trojan:Win64/Zusy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c1 43 32 04 10 4d 8d 40 01 2a c2 ff c2 42 88 44 05 2e 83 fa 10 7c e7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}