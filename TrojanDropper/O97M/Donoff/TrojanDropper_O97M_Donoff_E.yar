
rule TrojanDropper_O97M_Donoff_E{
	meta:
		description = "TrojanDropper:O97M/Donoff.E,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {52 65 70 6c 61 63 65 28 [0-10] 2c 20 22 64 6f 63 6d 22 2c 20 22 [0-10] 22 29 } //1
		$a_02_1 = {22 53 68 22 20 26 20 43 68 72 28 [0-10] 29 20 26 20 22 6c 6c 22 } //1
		$a_00_2 = {22 45 22 20 26 20 22 78 65 22 20 26 20 43 68 72 28 39 39 29 20 26 20 22 75 74 65 22 } //1 "E" & "xe" & Chr(99) & "ute"
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}