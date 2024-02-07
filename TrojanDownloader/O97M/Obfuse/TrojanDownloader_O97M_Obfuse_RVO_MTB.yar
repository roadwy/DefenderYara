
rule TrojanDownloader_O97M_Obfuse_RVO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 61 6e 67 65 28 22 46 46 31 32 30 30 22 29 2e 56 61 6c 75 65 } //01 00  Range("FF1200").Value
		$a_00_1 = {53 68 65 6c 6c 28 7a 6f 6f 6e 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29 } //01 00  Shell(zoon, vbNormalFocus)
		$a_00_2 = {78 78 78 78 20 3d 20 22 77 6f 72 6b 6f 75 74 2e 6a 73 22 } //01 00  xxxx = "workout.js"
		$a_00_3 = {7a 6f 6f 6e 20 3d 20 22 77 73 63 72 69 70 74 20 22 20 2b 20 6b 6f 6f 6c 78 78 78 78 } //01 00  zoon = "wscript " + koolxxxx
		$a_00_4 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //01 00  CreateObject("Scripting.FileSystemObject")
		$a_00_5 = {6f 46 69 6c 65 2e 57 72 69 74 65 4c 69 6e 65 20 6b 6f 6f 6e 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d 6d } //00 00  oFile.WriteLine koonmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm
	condition:
		any of ($a_*)
 
}