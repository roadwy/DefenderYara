
rule VirTool_WinNT_Rootkitdrv_CX{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.CX,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 05 00 00 "
		
	strings :
		$a_02_0 = {8d 0c 81 ff d6 0f 20 c0 0d 00 00 01 00 0f 22 c0 83 25 90 01 04 00 33 c0 40 5e 90 00 } //10
		$a_00_1 = {4e 00 65 00 74 00 57 00 6f 00 72 00 6b 00 73 00 2e 00 73 00 79 00 73 00 } //10 NetWorks.sys
		$a_00_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 4e 00 65 00 74 00 53 00 65 00 74 00 75 00 70 00 } //10 \Device\NetSetup
		$a_00_3 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 ZwQuerySystemInformation
		$a_00_4 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=32
 
}