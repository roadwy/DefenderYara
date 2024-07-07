
rule TrojanDropper_O97M_Obfuse_DD_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.DD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 61 75 74 6f 63 6c 6f 73 65 28 29 } //1 Sub autoclose()
		$a_00_1 = {3d 20 22 43 3a 5c 54 65 73 74 22 } //1 = "C:\Test"
		$a_00_2 = {2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e } //1 .Label1.Caption
		$a_00_3 = {50 72 69 6e 74 20 23 31 } //1 Print #1
		$a_03_4 = {20 26 20 22 5c 90 02 0a 2e 62 61 74 22 90 00 } //1
		$a_03_5 = {53 74 61 72 74 50 72 6f 63 65 73 73 20 22 43 3a 5c 54 65 73 74 5c 90 02 0a 2e 62 61 74 22 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}