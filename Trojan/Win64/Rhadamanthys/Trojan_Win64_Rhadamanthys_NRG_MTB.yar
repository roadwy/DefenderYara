
rule Trojan_Win64_Rhadamanthys_NRG_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NRG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_81_0 = {43 68 61 69 6e 69 6e 67 4d 6f 64 65 43 42 43 } //1 ChainingModeCBC
		$a_81_1 = {42 43 72 79 70 74 44 65 63 72 79 70 74 } //1 BCryptDecrypt
		$a_01_2 = {66 0f 6e ca 66 0f 70 c9 00 f3 41 0f 6f 02 49 83 c2 10 66 0f ef c1 41 0f 11 42 } //2
		$a_01_3 = {48 0f af d1 48 c1 ea 24 8d 14 92 c1 e2 02 29 d0 83 f8 13 } //3
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*3) >=7
 
}