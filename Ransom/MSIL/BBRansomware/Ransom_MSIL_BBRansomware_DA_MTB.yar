
rule Ransom_MSIL_BBRansomware_DA_MTB{
	meta:
		description = "Ransom:MSIL/BBRansomware.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {42 42 20 72 61 6e 73 6f 6d 77 61 72 65 } //1 BB ransomware
		$a_81_1 = {2e 65 6e 63 72 79 70 74 65 64 } //1 .encrypted
		$a_81_2 = {57 72 6f 6e 67 20 63 6f 64 65 2e 20 48 61 68 61 68 61 } //1 Wrong code. Hahaha
		$a_81_3 = {53 75 63 63 65 73 73 20 44 65 63 72 79 70 74 } //1 Success Decrypt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}