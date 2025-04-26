
rule Trojan_Win32_GuLoader_RBE_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_81_0 = {61 69 6c 73 20 67 6e 61 74 68 69 63 20 61 66 73 6b 72 6b 6b 65 6c 73 65 73 76 61 61 62 6e 65 74 } //1 ails gnathic afskrkkelsesvaabnet
		$a_81_1 = {6d 65 73 6f 73 69 67 6d 6f 69 64 20 75 64 66 79 6c 64 6e 69 6e 67 72 73 } //1 mesosigmoid udfyldningrs
		$a_81_2 = {79 6f 72 20 73 65 62 75 6d 20 64 69 73 63 72 65 65 74 } //1 yor sebum discreet
		$a_81_3 = {75 73 69 6b 6b 65 72 68 65 64 73 6d 6f 6d 65 6e 74 65 74 73 20 64 65 6b 6f 64 6e 69 6e 67 65 72 73 2e 65 78 65 } //1 usikkerhedsmomentets dekodningers.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=3
 
}