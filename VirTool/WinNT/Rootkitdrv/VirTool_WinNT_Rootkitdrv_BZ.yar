
rule VirTool_WinNT_Rootkitdrv_BZ{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.BZ,SIGNATURE_TYPE_PEHSTR_EXT,2c 00 2c 00 08 00 00 0a 00 "
		
	strings :
		$a_02_0 = {c1 e8 08 33 02 25 ff ff 00 00 a3 90 01 04 75 07 8b c1 a3 90 01 04 f7 d0 a3 90 01 04 5d e9 90 00 } //0a 00 
		$a_00_1 = {5a 77 51 75 65 72 79 44 69 72 65 63 74 6f 72 79 46 69 6c 65 } //0a 00  ZwQueryDirectoryFile
		$a_00_2 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //0a 00  ZwQuerySystemInformation
		$a_00_3 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00  KeServiceDescriptorTable
		$a_00_4 = {68 69 64 65 } //01 00  hide
		$a_00_5 = {72 6f 6f 74 } //01 00  root
		$a_00_6 = {55 6e 64 65 61 64 } //01 00  Undead
		$a_00_7 = {72 6f 6f 74 6b 69 74 } //00 00  rootkit
	condition:
		any of ($a_*)
 
}