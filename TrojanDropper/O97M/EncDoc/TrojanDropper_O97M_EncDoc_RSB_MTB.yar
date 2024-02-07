
rule TrojanDropper_O97M_EncDoc_RSB_MTB{
	meta:
		description = "TrojanDropper:O97M/EncDoc.RSB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {77 77 77 2e 64 61 69 63 68 69 2e 63 6f 2e 69 6e 2f 76 6d 6c 78 76 76 66 68 69 6a 72 2f 35 35 35 35 35 35 35 35 35 2e 70 6e 67 90 0a 31 00 68 74 74 70 3a 2f 2f 90 00 } //01 00 
		$a_01_1 = {43 3a 5c 46 65 74 69 6c 5c 47 69 6f 6c 61 5c 6f 63 65 61 6e 44 68 } //00 00  C:\Fetil\Giola\oceanDh
	condition:
		any of ($a_*)
 
}