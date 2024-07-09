
rule VirTool_WinNT_Rootkitdrv_AU{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.AU,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 63 20 64 65 6c 20 25 73 20 3e 20 6e 75 6c } //10 /c del %s > nul
		$a_02_1 = {4e 65 74 42 6f 74 5c 69 33 38 36 5c [0-08] 2e 70 64 62 } //10
		$a_00_2 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //10 Microsoft Corporation
		$a_00_3 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //10 KeServiceDescriptorTable
		$a_00_4 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //10 CreateToolhelp32Snapshot
		$a_02_5 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 07 8b 4d ?? 89 04 8b 0f 20 c0 0d 00 00 01 00 0f 22 c0 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_02_5  & 1)*1) >=51
 
}