
rule Trojan_O97M_Obfuse_BP{
	meta:
		description = "Trojan:O97M/Obfuse.BP,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //01 00  Sub AutoOpen()
		$a_00_1 = {20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 } //01 00   = Environ("Temp")
		$a_00_2 = {20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 73 63 72 69 70 74 69 6e 67 2e 66 69 6c 65 73 79 73 74 65 6d 6f 62 6a 65 63 74 22 29 } //01 00   = CreateObject("scripting.filesystemobject")
		$a_00_3 = {20 3d 20 45 6e 76 69 72 6f 6e 28 22 53 79 73 74 65 6d 52 6f 6f 74 22 29 } //01 00   = Environ("SystemRoot")
		$a_00_4 = {0d 0a 53 68 65 6c 6c 20 } //01 00 
		$a_02_5 = {53 65 6c 65 63 74 20 43 61 73 65 20 90 02 20 0d 0a 43 61 73 65 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}