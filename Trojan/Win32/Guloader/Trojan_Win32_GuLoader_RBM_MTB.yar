
rule Trojan_Win32_GuLoader_RBM_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {63 61 6c 6c 69 74 79 70 65 64 20 61 77 61 72 75 69 74 65 20 6d 65 73 72 6f 70 69 61 6e } //1 callityped awaruite mesropian
		$a_81_1 = {75 6e 64 65 72 73 61 74 75 72 61 74 69 6f 6e 20 6e 75 6d 62 65 72 6f 75 73 } //1 undersaturation numberous
		$a_81_2 = {72 61 61 76 61 72 65 70 72 69 73 } //1 raavarepris
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}