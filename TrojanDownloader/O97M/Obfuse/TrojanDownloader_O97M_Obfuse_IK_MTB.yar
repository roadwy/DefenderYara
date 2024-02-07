
rule TrojanDownloader_O97M_Obfuse_IK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.IK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 6a 73 22 } //01 00  .js"
		$a_01_1 = {3d 20 22 77 69 6e 64 69 72 22 } //01 00  = "windir"
		$a_01_2 = {3d 20 45 6e 76 69 72 6f 6e 28 45 29 20 2b 20 22 5c 54 65 6d 70 22 } //01 00  = Environ(E) + "\Temp"
		$a_01_3 = {46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 } //01 00  For Output As #
		$a_01_4 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 2e 4f 70 65 6e 20 72 65 61 6c 70 61 74 68 } //01 00  CreateObject("Shell.Application").Open realpath
		$a_01_5 = {2e 43 6f 6e 74 72 6f 6c 73 28 30 29 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 } //01 00  .Controls(0).ControlTipText
		$a_01_6 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //00 00  Sub AutoOpen()
	condition:
		any of ($a_*)
 
}