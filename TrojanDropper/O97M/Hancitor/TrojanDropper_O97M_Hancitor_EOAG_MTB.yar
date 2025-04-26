
rule TrojanDropper_O97M_Hancitor_EOAG_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOAG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 6e 76 69 72 6f 6e 24 28 22 74 65 6d 70 22 29 20 26 20 22 5c 6f 6d 73 68 2e 64 6c 6c 2c } //1 Environ$("temp") & "\omsh.dll,
		$a_01_1 = {75 73 78 20 3d 20 45 6e 76 69 72 6f 6e 24 28 22 74 65 6d 70 22 29 } //1 usx = Environ$("temp")
		$a_03_2 = {41 63 74 69 76 65 53 68 65 65 74 2e 53 68 61 70 65 73 2e 52 61 6e 67 65 28 41 72 72 61 79 28 22 4f 62 6a 65 63 74 20 [0-03] 22 29 29 2e 53 65 6c 65 63 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}