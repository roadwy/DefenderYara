
rule Trojan_Linux_Pupy_C_MTB{
	meta:
		description = "Trojan:Linux/Pupy.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 65 66 6c 65 63 74 69 76 65 5f 69 6e 6a 65 63 74 5f 64 6c 6c } //1 reflective_inject_dll
		$a_01_1 = {67 65 74 5f 70 75 70 79 5f 63 6f 6e 66 69 67 } //1 get_pupy_config
		$a_01_2 = {6c 69 6e 75 78 2d 69 6e 6a 65 63 74 } //1 linux-inject
		$a_01_3 = {70 75 70 79 2e 65 72 72 6f 72 } //1 pupy.error
		$a_01_4 = {69 6e 6a 65 63 74 53 68 61 72 65 64 4c 69 62 72 61 72 79 } //1 injectSharedLibrary
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}