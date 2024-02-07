
rule VirTool_WinNT_Rootkitdrv_GX{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.GX,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {50 0f 20 c0 25 ff ff fe ff 0f 22 c0 58 80 7d 08 00 } //02 00 
		$a_03_1 = {8b 49 01 8b 12 b8 90 01 02 01 00 8d 0c 8a 87 01 a3 90 01 02 01 00 90 00 } //02 00 
		$a_01_2 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00  KeServiceDescriptorTable
		$a_01_3 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //01 00  ZwQuerySystemInformation
		$a_01_4 = {5a 77 51 75 65 72 79 44 69 72 65 63 74 6f 72 79 46 69 6c 65 } //00 00  ZwQueryDirectoryFile
	condition:
		any of ($a_*)
 
}