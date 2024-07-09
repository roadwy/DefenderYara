
rule TrojanDropper_O97M_Donoff_CS_eml{
	meta:
		description = "TrojanDropper:O97M/Donoff.CS!eml,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 73 67 42 6f 78 20 28 22 44 6f 63 75 6d 65 6e 74 20 64 65 63 72 79 70 74 20 65 72 72 6f 72 2e 22 29 } //1 MsgBox ("Document decrypt error.")
		$a_01_1 = {2e 46 69 6e 64 2e 45 78 65 63 75 74 65 20 52 65 70 6c 61 63 65 3a 3d 77 64 52 65 70 6c 61 63 65 41 6c 6c } //1 .Find.Execute Replace:=wdReplaceAll
		$a_03_2 = {46 69 6c 65 43 6f 70 79 20 4a 6f 69 6e 28 [0-0c] 2c 20 22 22 29 } //1
		$a_03_3 = {53 68 65 6c 6c 20 4a 6f 69 6e 28 [0-0d] 2c 20 22 22 29 } //1
		$a_00_4 = {76 61 6c 75 65 4f 6e 65 20 3d 20 22 54 48 49 53 20 49 53 20 54 48 45 20 50 52 4f 44 55 43 54 22 } //1 valueOne = "THIS IS THE PRODUCT"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}