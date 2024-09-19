
rule VirTool_Win64_Killepesz_A_MTB{
	meta:
		description = "VirTool:Win64/Killepesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 65 6d 6f 76 65 64 20 50 50 4c } //1 Removed PPL
		$a_01_1 = {49 4f 43 54 4c 5f 50 50 4c 4b 5f 55 4e 50 52 4f 54 45 43 54 } //1 IOCTL_PPLK_UNPROTECT
		$a_03_2 = {64 69 73 61 62 6c 65 [0-20] 6d 69 74 69 67 61 74 69 6f 6e } //1
		$a_01_3 = {44 72 69 76 65 72 20 75 6e 6c 6f 61 64 65 64 } //1 Driver unloaded
		$a_01_4 = {72 6f 6f 74 6b 69 74 } //1 rootkit
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}