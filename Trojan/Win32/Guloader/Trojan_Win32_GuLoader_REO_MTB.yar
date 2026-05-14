
rule Trojan_Win32_GuLoader_REO_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.REO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {66 69 62 72 69 6e 61 74 65 } //1 fibrinate
		$a_81_1 = {62 65 6b 6c 61 67 65 6c 69 67 65 72 65 73 20 6d 61 64 6d 6f 72 73 20 74 72 65 73 73 69 65 73 74 } //1 beklageligeres madmors tressiest
		$a_81_2 = {68 61 72 75 73 70 69 63 79 } //1 haruspicy
		$a_81_3 = {62 61 6c 75 63 68 69 74 68 65 72 69 61 20 6d 75 63 6b 65 64 2e 65 78 65 } //1 baluchitheria mucked.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}