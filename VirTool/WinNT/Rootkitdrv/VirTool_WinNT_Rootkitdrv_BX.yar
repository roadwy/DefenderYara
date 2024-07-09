
rule VirTool_WinNT_Rootkitdrv_BX{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.BX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {bf 0d 00 00 c0 eb ?? 8b 08 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 03 89 04 91 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb } //1
		$a_00_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 52 00 45 00 53 00 53 00 44 00 54 00 } //1 \Device\RESSDT
		$a_00_2 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
		$a_00_3 = {5c 63 6f 64 65 5c 52 45 53 53 44 54 5c 69 33 38 36 5c 52 45 53 53 44 54 2e 70 64 62 } //1 \code\RESSDT\i386\RESSDT.pdb
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}