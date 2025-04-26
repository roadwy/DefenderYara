
rule Trojan_Win64_MedusaLocker_YAC_MTB{
	meta:
		description = "Trojan:Win64/MedusaLocker.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 00 61 00 62 00 79 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 4b 00 5a 00 } //3 BabyLockerKZ
		$a_01_1 = {48 8b c3 49 f7 f7 48 8b 06 0f b6 0c 0a 41 32 0c 18 88 0c 03 48 ff c3 } //12
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*12) >=15
 
}