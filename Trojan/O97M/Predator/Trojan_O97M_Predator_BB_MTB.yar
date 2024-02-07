
rule Trojan_O97M_Predator_BB_MTB{
	meta:
		description = "Trojan:O97M/Predator.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 4d 4c 32 2e 44 4f 4d 44 6f 63 75 6d 65 6e 74 22 29 2e 43 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 64 75 6d 6d 79 22 29 } //01 00  VBA.CreateObject("MSXML2.DOMDocument").CreateElement("dummy")
		$a_01_1 = {2e 44 61 74 61 54 79 70 65 20 3d 20 22 62 69 6e 22 20 2b 20 22 2e 62 61 73 65 36 34 22 } //01 00  .DataType = "bin" + ".base64"
		$a_03_2 = {53 65 74 20 90 02 0a 3d 90 02 0a 2e 43 6f 6e 6e 65 63 74 53 65 72 76 65 72 28 29 90 02 20 2e 53 65 63 75 72 69 74 79 5f 2e 49 6d 70 65 72 73 6f 6e 61 74 69 6f 6e 4c 65 76 65 6c 20 3d 20 35 36 20 5f 90 02 0a 2a 20 32 20 5f 90 02 0a 20 2d 20 31 30 39 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}