
rule VirTool_WinNT_Rootkitdrv_CM{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.CM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 41 01 8b 0d ?? ?? 01 00 8b 09 c7 04 81 } //2
		$a_01_1 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
		$a_00_2 = {53 79 73 74 65 6d 00 56 57 ff 15 } //1
		$a_01_3 = {0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 5f 5e 5b c3 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*2) >=4
 
}