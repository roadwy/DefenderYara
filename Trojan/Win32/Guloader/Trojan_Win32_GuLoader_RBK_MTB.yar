
rule Trojan_Win32_GuLoader_RBK_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {62 6f 6d 62 61 72 64 65 6d 65 6e 74 73 20 73 6b 61 74 74 65 72 65 66 6f 72 6d 65 6e } //1 bombardements skattereformen
		$a_81_1 = {75 6d 6d 70 73 20 76 69 6e 6b 65 6c 68 61 73 74 69 67 68 65 64 65 72 6e 65 73 } //1 ummps vinkelhastighedernes
		$a_81_2 = {73 6b 72 69 67 65 6e 65 73 } //1 skrigenes
		$a_81_3 = {64 6f 6c 63 61 6e 2e 65 78 65 } //1 dolcan.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}