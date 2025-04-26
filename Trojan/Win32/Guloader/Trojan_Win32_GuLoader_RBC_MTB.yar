
rule Trojan_Win32_GuLoader_RBC_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 62 69 62 6c 69 6f 67 72 61 66 65 72 73 2e 74 6f 6c } //1 \bibliografers.tol
		$a_81_1 = {5c 46 6c 69 6d 70 31 33 37 } //1 \Flimp137
		$a_81_2 = {73 6b 62 6e 65 62 65 73 74 65 6d 74 65 20 63 6f 72 6f 64 69 61 72 79 } //1 skbnebestemte corodiary
		$a_81_3 = {6b 69 6b 6f 72 69 } //1 kikori
		$a_81_4 = {72 65 67 69 73 74 65 72 6e 61 76 6e 65 6e 65 73 } //1 registernavnenes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}