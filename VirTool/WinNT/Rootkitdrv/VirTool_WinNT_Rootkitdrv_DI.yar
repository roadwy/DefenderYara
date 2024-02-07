
rule VirTool_WinNT_Rootkitdrv_DI{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.DI,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 08 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 06 8b 90 01 02 89 04 99 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 90 00 } //02 00 
		$a_00_1 = {5c 00 46 00 55 00 43 00 4b 00 58 00 53 00 53 00 44 00 54 00 } //02 00  \FUCKXSSDT
		$a_00_2 = {46 75 63 6b 20 44 69 73 50 61 74 63 68 } //01 00  Fuck DisPatch
		$a_00_3 = {4d 61 6b 65 20 48 65 78 69 65 20 43 68 69 6e 61 21 } //01 00  Make Hexie China!
		$a_00_4 = {57 68 61 74 20 43 61 6e 20 59 6f 75 20 44 6f 3f } //01 00  What Can You Do?
		$a_00_5 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 53 00 4e 00 53 00 53 00 44 00 54 00 } //01 00  \Device\SNSSDT
		$a_00_6 = {5c 52 45 53 53 44 54 5c 69 33 38 36 5c 52 45 53 53 44 54 2e 70 64 62 } //01 00  \RESSDT\i386\RESSDT.pdb
		$a_00_7 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //00 00  Microsoft Corporation
	condition:
		any of ($a_*)
 
}