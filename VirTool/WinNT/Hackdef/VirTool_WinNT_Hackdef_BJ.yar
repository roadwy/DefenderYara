
rule VirTool_WinNT_Hackdef_BJ{
	meta:
		description = "VirTool:WinNT/Hackdef.BJ,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {2e 45 78 65 53 61 78 00 } //0a 00  䔮數慓x
		$a_02_1 = {2d 00 20 22 00 0f 84 90 01 01 00 00 00 6a 04 59 2b c1 74 90 01 01 89 1e 89 4f 1c c7 45 90 01 01 10 00 00 c0 90 00 } //0a 00 
		$a_00_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 4d 00 53 00 44 00 56 00 44 00 44 00 72 00 69 00 76 00 65 00 72 00 } //0a 00  \Device\MSDVDDriver
		$a_00_3 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 4d 00 53 00 44 00 56 00 44 00 44 00 72 00 69 00 76 00 65 00 72 00 } //01 00  \DosDevices\MSDVDDriver
		$a_00_4 = {5a 77 4f 70 65 6e 50 72 6f 63 65 73 73 } //01 00  ZwOpenProcess
		$a_00_5 = {4b 65 41 74 74 61 63 68 50 72 6f 63 65 73 73 } //01 00  KeAttachProcess
		$a_00_6 = {5a 77 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } //00 00  ZwSetInformationProcess
	condition:
		any of ($a_*)
 
}