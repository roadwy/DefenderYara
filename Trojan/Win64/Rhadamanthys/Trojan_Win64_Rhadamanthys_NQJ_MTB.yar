
rule Trojan_Win64_Rhadamanthys_NQJ_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NQJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {43 68 61 69 6e 69 6e 67 4d 6f 64 65 43 42 43 } //1 ChainingModeCBC
		$a_81_1 = {42 43 72 79 70 74 44 65 63 72 79 70 74 } //1 BCryptDecrypt
		$a_03_2 = {66 0f 6e c0 66 41 81 72 ?? ?? ?? 66 0f 70 c0 00 66 0f ef c8 } //2
		$a_03_3 = {66 0f 71 f2 ?? 66 0f db d1 66 0f f8 c2 f3 41 0f 6f 51 } //2
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=4
 
}