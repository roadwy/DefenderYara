
rule HackTool_Win32_Loader_MTB{
	meta:
		description = "HackTool:Win32/Loader!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {4c 69 67 68 74 42 75 72 6e 2e 65 78 65 } //LightBurn.exe  2
		$a_80_1 = {4a 6f 68 6e 44 6f 65 } //JohnDoe  1
		$a_80_2 = {4e 6f 74 68 69 6e 67 20 74 6f 20 70 61 74 63 68 21 20 65 78 69 74 69 6e 67 2e 2e } //Nothing to patch! exiting..  1
		$a_80_3 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_4 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*-100+(#a_80_4  & 1)*-100) >=4
 
}