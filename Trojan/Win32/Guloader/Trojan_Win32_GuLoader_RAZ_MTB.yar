
rule Trojan_Win32_GuLoader_RAZ_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {70 6f 6c 63 70 72 20 76 69 6e 64 69 63 61 74 69 76 65 6c 79 20 61 66 73 69 67 65 6e 64 65 } //1 polcpr vindicatively afsigende
		$a_81_1 = {75 6e 63 6f 67 65 6e 74 6c 79 20 69 6e 67 75 6c 66 } //1 uncogently ingulf
		$a_81_2 = {6c 61 74 65 77 61 72 64 20 6c 6f 66 74 73 62 65 6c 79 73 6e 69 6e 67 65 6e 73 20 67 65 6e 65 76 69 75 67 76 65 73 } //1 lateward loftsbelysningens geneviugves
		$a_81_3 = {62 61 73 73 65 74 74 20 75 6e 63 61 73 65 73 20 72 65 6e 65 67 6c 65 63 74 } //1 bassett uncases reneglect
		$a_81_4 = {6c 69 67 67 65 70 6c 61 64 73 20 76 61 6c 65 6e 74 69 6e 6f 2e 65 78 65 } //1 liggeplads valentino.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}