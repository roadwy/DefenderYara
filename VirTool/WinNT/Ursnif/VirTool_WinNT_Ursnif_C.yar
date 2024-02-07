
rule VirTool_WinNT_Ursnif_C{
	meta:
		description = "VirTool:WinNT/Ursnif.C,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 06 8d 04 3e 50 68 90 01 03 00 ff 15 90 01 03 00 83 c4 0c 85 c0 75 06 89 35 90 01 03 00 46 81 fe 00 30 00 00 7c d9 90 00 } //01 00 
		$a_00_1 = {49 6e 74 65 72 6c 6f 63 6b 65 64 45 78 63 68 61 6e 67 65 } //01 00  InterlockedExchange
		$a_00_2 = {5a 77 45 6e 75 6d 65 72 61 74 65 56 61 6c 75 65 4b 65 79 } //01 00  ZwEnumerateValueKey
		$a_00_3 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00  KeServiceDescriptorTable
		$a_00_4 = {5a 77 51 75 65 72 79 44 69 72 65 63 74 6f 72 79 46 69 6c 65 } //01 00  ZwQueryDirectoryFile
		$a_00_5 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //01 00  ZwQuerySystemInformation
		$a_00_6 = {68 69 64 65 5f 65 76 72 32 2e 70 64 62 } //00 00  hide_evr2.pdb
	condition:
		any of ($a_*)
 
}