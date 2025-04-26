
rule Ransom_MSIL_ReviL_DA_MTB{
	meta:
		description = "Ransom:MSIL/ReviL.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {50 6f 76 6c 73 6f 6d 77 61 72 65 } //1 Povlsomware
		$a_81_1 = {45 6e 63 72 79 70 74 65 64 } //1 Encrypted
		$a_81_2 = {52 61 6e 73 6f 6d 65 76 69 4c } //1 RansomeviL
		$a_81_3 = {57 69 6e 33 32 5f 53 68 61 64 6f 77 43 6f 70 79 } //1 Win32_ShadowCopy
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}