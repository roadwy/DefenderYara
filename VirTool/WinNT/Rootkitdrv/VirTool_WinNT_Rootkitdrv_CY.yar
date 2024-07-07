
rule VirTool_WinNT_Rootkitdrv_CY{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.CY,SIGNATURE_TYPE_PEHSTR,15 00 15 00 05 00 00 "
		
	strings :
		$a_01_0 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 06 8b 4d e0 89 04 99 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb } //10
		$a_01_1 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //10 KeServiceDescriptorTable
		$a_01_2 = {5c 41 6e 74 69 44 72 69 76 65 72 2e 70 64 62 } //1 \AntiDriver.pdb
		$a_01_3 = {5c 58 4e 47 5f 41 6e 74 69 56 65 72 73 69 6f 6e } //1 \XNG_AntiVersion
		$a_01_4 = {5c 44 65 76 69 63 65 5c 58 4e 47 41 6e 74 69 } //1 \Device\XNGAnti
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=21
 
}