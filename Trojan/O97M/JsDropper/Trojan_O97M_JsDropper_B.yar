
rule Trojan_O97M_JsDropper_B{
	meta:
		description = "Trojan:O97M/JsDropper.B,SIGNATURE_TYPE_MACROHSTR_EXT,15 00 14 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {3d 20 22 53 65 74 20 90 02 10 20 3d 20 4e 65 77 20 90 02 10 20 46 6f 72 20 45 61 63 68 20 90 02 10 20 49 6e 20 90 02 10 20 57 68 69 6c 65 20 4e 6f 74 20 90 02 10 20 22 90 00 } //01 00 
		$a_00_1 = {2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 } //0a 00  .AttachedTemplate.Path
		$a_00_2 = {26 20 22 2e 6a 73 65 22 } //01 00  & ".jse"
		$a_00_3 = {57 73 68 53 63 72 69 70 74 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 } //01 00  WshScript.ShellExecute
		$a_02_4 = {4f 70 65 6e 20 90 02 10 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}