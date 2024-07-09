
rule VirTool_WinNT_Rootkitdrv_DL{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.DL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 4d ?? 8b 55 ?? 8b 45 ?? 8b 00 89 04 8a 0f 20 c0 0d 00 00 01 00 0f 22 c0 } //1
		$a_00_1 = {5c 31 5c 69 33 38 36 5c 52 45 53 53 44 54 2e 70 64 62 } //1 \1\i386\RESSDT.pdb
		$a_00_2 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}