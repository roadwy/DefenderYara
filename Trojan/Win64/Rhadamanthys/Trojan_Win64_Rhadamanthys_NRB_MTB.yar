
rule Trojan_Win64_Rhadamanthys_NRB_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_81_0 = {43 68 61 69 6e 69 6e 67 4d 6f 64 65 43 42 43 } //1 ChainingModeCBC
		$a_81_1 = {42 43 72 79 70 74 44 65 63 72 79 70 74 } //1 BCryptDecrypt
		$a_03_2 = {66 0f fc c1 66 0f 71 d1 ?? 66 0f fc c0 66 0f db ca 66 0f fc c0 66 0f eb c1 } //3
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_03_2  & 1)*3) >=5
 
}