
rule TrojanDropper_O97M_Obfuse_AA_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.AA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  CreateObject("WScript.Shell")
		$a_03_1 = {52 65 67 57 72 69 74 65 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 90 02 25 22 2c 20 22 22 22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 61 22 22 22 22 68 90 02 25 3a 22 20 2b 20 22 5c 22 20 2b 20 22 5c 22 20 2b 20 22 6a 22 20 2b 20 22 2e 22 20 2b 20 22 6d 22 20 2b 20 22 70 22 20 2b 20 22 5c 90 02 25 22 22 22 2c 20 22 52 45 47 5f 53 5a 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}