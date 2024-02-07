
rule TrojanDownloader_O97M_Obfuse_PREG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PREG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 75 62 61 75 74 6f 5f 6f 70 65 6e 28 29 64 69 6d 73 68 65 6c 6c 61 73 6f 62 6a 65 63 74 64 69 6d 63 6f 6d 6d 61 6e 64 61 73 73 74 72 69 6e 67 27 73 70 65 63 69 66 79 74 68 65 70 6f 77 65 72 73 68 65 6c 6c 63 6f 6d 6d 61 6e 64 79 6f 75 77 61 6e 74 74 6f 72 75 6e 63 6f 6d 6d 61 6e 64 3d 22 67 65 74 2d 70 72 6f 63 65 73 73 22 27 63 72 65 61 74 65 61 6e 65 77 73 68 65 6c 6c 6f 62 6a 65 63 74 73 65 74 73 68 65 6c 6c 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 27 } //01 00  subauto_open()dimshellasobjectdimcommandasstring'specifythepowershellcommandyouwanttoruncommand="get-process"'createanewshellobjectsetshell=createobject("wscript.shell")'
		$a_03_1 = {6f 70 65 6e 70 6f 77 65 72 73 68 65 6c 6c 61 6e 64 72 75 6e 74 68 65 63 6f 6d 6d 61 6e 64 73 68 65 6c 6c 2e 72 75 6e 22 70 6f 77 65 72 73 68 65 6c 6c 26 70 6f 77 65 72 73 68 65 6c 6c 28 6e 73 6c 6f 6f 6b 75 70 2d 71 3d 74 78 74 90 02 0f 2e 61 62 65 6e 61 2d 64 6b 2e 63 61 6d 29 5b 2d 31 5d 2d 6e 6f 6e 65 77 77 69 6e 64 6f 77 22 2c 30 2c 66 61 6c 73 65 27 72 65 6c 65 61 73 65 74 68 65 73 68 65 6c 6c 6f 62 6a 65 63 74 73 65 74 73 68 65 6c 6c 3d 6e 6f 74 68 69 6e 67 65 6e 64 73 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}