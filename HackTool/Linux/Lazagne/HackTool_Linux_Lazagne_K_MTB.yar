
rule HackTool_Linux_Lazagne_K_MTB{
	meta:
		description = "HackTool:Linux/Lazagne.K!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {6c 61 7a 61 67 6e 65 2e 63 6f 6e 66 69 67 } //1 lazagne.config
		$a_00_1 = {6c 61 7a 61 67 6e 65 2e 73 6f 66 74 77 61 72 65 73 } //1 lazagne.softwares
		$a_00_2 = {73 6c 61 5a 61 67 6e 65 } //1 slaZagne
		$a_00_3 = {43 61 6e 6e 6f 74 20 73 69 64 65 2d 6c 6f 61 64 20 65 78 74 65 72 6e 61 6c 20 61 72 63 68 69 76 65 20 25 73 20 28 63 6f 64 65 20 25 64 29 } //1 Cannot side-load external archive %s (code %d)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}