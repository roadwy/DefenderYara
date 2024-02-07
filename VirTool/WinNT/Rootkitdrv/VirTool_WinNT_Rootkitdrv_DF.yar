
rule VirTool_WinNT_Rootkitdrv_DF{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.DF,SIGNATURE_TYPE_PEHSTR_EXT,79 00 79 00 06 00 00 64 00 "
		
	strings :
		$a_02_0 = {80 38 4d 75 90 01 01 80 78 01 5a 75 90 01 01 89 45 d8 8b 48 3c 03 c8 89 4d d4 74 08 81 39 50 45 00 00 90 00 } //0a 00 
		$a_00_1 = {70 6f 72 74 20 74 6f 20 68 69 64 65 } //0a 00  port to hide
		$a_00_2 = {5c 48 69 64 65 44 72 69 76 65 72 2e 70 64 62 } //0a 00  \HideDriver.pdb
		$a_00_3 = {48 6f 6f 6b 5a 77 44 65 76 69 63 65 49 6f 43 6f 6e 74 72 6f 6c 46 69 6c 65 } //01 00  HookZwDeviceIoControlFile
		$a_00_4 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00  KeServiceDescriptorTable
		$a_00_5 = {4b 65 41 64 64 53 79 73 74 65 6d 53 65 72 76 69 63 65 54 61 62 6c 65 } //00 00  KeAddSystemServiceTable
	condition:
		any of ($a_*)
 
}