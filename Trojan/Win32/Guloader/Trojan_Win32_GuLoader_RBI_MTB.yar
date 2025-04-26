
rule Trojan_Win32_GuLoader_RBI_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {42 75 72 6c 69 6e 67 74 6f 6e 20 52 65 73 6f 75 72 63 65 73 20 49 6e 63 2e } //1 Burlington Resources Inc.
		$a_81_1 = {42 6f 77 61 74 65 72 20 49 6e 63 6f 72 70 6f 72 61 74 65 64 } //1 Bowater Incorporated
		$a_81_2 = {53 69 65 62 65 6c 20 53 79 73 74 65 6d 73 20 49 6e 63 } //1 Siebel Systems Inc
		$a_81_3 = {4c 61 6e 64 73 74 61 72 20 53 79 73 74 65 6d 20 49 6e 63 2e } //1 Landstar System Inc.
		$a_81_4 = {66 69 65 6e 64 6c 69 6e 65 73 73 20 68 6f 72 72 6f 72 66 75 6c 2e 65 78 65 } //1 fiendliness horrorful.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}