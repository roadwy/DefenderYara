
rule Trojan_Win32_GuLoader_RSZ_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {69 6e 76 65 6e 74 69 6f 6e 20 74 79 6e 67 64 65 70 75 6e 6b 74 73 66 6f 72 73 6b 79 64 6e 69 6e 67 65 72 6e 65 } //1 invention tyngdepunktsforskydningerne
		$a_81_1 = {62 65 73 6b 61 74 6e 69 6e 67 73 66 6f 72 6d 65 72 73 20 75 6e 64 65 72 73 70 69 6c 6e 69 6e 67 65 6e 73 } //1 beskatningsformers underspilningens
		$a_81_2 = {66 6f 6c 6b 65 74 72 6f 65 6e 20 63 6c 61 64 6f 63 65 72 6f 75 73 } //1 folketroen cladocerous
		$a_81_3 = {73 75 72 6d 6c 6b 20 73 63 72 65 61 6d 73 20 63 69 73 73 65 74 } //1 surmlk screams cisset
		$a_81_4 = {73 6b 69 6e 6e 65 62 75 73 73 65 72 6e 65 } //1 skinnebusserne
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}