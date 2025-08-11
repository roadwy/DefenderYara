
rule Trojan_Win32_GuLoader_RAI_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {62 72 61 63 68 69 61 74 61 20 68 79 70 68 65 6e 61 74 69 6f 6e 20 65 6c 65 63 74 72 6f 74 6f 6e 69 73 65 } //1 brachiata hyphenation electrotonise
		$a_81_1 = {6d 6f 6f 6c 73 } //1 mools
		$a_81_2 = {70 6f 73 6f 6c 6f 67 69 63 20 72 69 74 2e 65 78 65 } //1 posologic rit.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}