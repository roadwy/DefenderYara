
rule HackTool_Win32_Keygen_MSR{
	meta:
		description = "HackTool:Win32/Keygen!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {45 61 73 65 55 53 5f 44 52 57 2e 65 78 65 } //EaseUS_DRW.exe  1
		$a_80_1 = {41 63 74 69 76 61 74 65 64 } //Activated  1
		$a_80_2 = {72 6f 6f 74 5c 43 49 4d 56 32 } //root\CIMV2  1
		$a_80_3 = {6f 72 70 68 61 6e 20 70 61 63 6b 61 67 65 } //orphan package  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule HackTool_Win32_Keygen_MSR_2{
	meta:
		description = "HackTool:Win32/Keygen!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {41 43 4b 4e 4f 57 4c 45 44 47 45 20 2d 42 52 4b 2d } //ACKNOWLEDGE -BRK-  1
		$a_80_1 = {47 65 6e 65 72 61 74 65 } //Generate  1
		$a_80_2 = {6e 6f 72 77 69 63 68 2e 6e 65 74 } //norwich.net  1
		$a_80_3 = {4b 65 79 67 65 6e } //Keygen  1
		$a_80_4 = {42 4b 54 2f 42 52 44 } //BKT/BRD  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}