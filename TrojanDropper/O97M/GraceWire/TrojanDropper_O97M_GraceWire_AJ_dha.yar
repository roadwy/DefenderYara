
rule TrojanDropper_O97M_GraceWire_AJ_dha{
	meta:
		description = "TrojanDropper:O97M/GraceWire.AJ!dha,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {3d 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 32 2e 54 61 67 20 2b 20 22 5c 6c 69 62 44 78 64 69 61 67 [0-05] 22 } //1
		$a_00_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 22 20 2b 20 22 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 CreateObject("Shell." + "Application")
		$a_02_2 = {6f 41 70 70 2e 4e 61 6d 65 73 70 61 63 65 28 [0-10] 29 2e 43 6f 70 79 48 65 72 65 20 6f 41 70 70 2e 4e 61 6d 65 73 70 61 63 65 28 [0-10] 29 2e 69 74 65 6d 73 2e 49 74 65 6d } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}