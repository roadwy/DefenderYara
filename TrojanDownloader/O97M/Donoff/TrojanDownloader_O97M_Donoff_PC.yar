
rule TrojanDownloader_O97M_Donoff_PC{
	meta:
		description = "TrojanDownloader:O97M/Donoff.PC,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {53 68 65 6c 6c 20 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 43 6f 6d 6d 65 6e 74 73 22 29 2e 56 61 6c 75 65 29 90 02 10 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_PC_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.PC,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 22 53 59 53 54 45 4d 53 } //01 00  = "SYSTEMS
		$a_00_1 = {3d 20 22 2e 6a 73 65 } //01 00  = ".jse
		$a_00_2 = {3d 20 41 72 72 61 79 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 2c 20 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //01 00  = Array("USERPROFILE", "Scripting.FileSystemObject")
		$a_02_3 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 90 02 15 2c 20 54 72 75 65 2c 20 54 72 75 65 29 90 00 } //01 00 
		$a_00_4 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 } //00 00  .ShellExecute
	condition:
		any of ($a_*)
 
}