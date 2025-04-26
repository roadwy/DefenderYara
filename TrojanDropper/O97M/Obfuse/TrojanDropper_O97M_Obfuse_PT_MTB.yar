
rule TrojanDropper_O97M_Obfuse_PT_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.PT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 2f [0-05] 2e 6a 73 22 } //1
		$a_01_1 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 2e 5c 72 6f 6f 74 5c 63 69 6d 76 32 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //1 = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
		$a_01_2 = {28 54 65 6d 70 2c 20 22 5c 22 29 } //1 (Temp, "\")
		$a_01_3 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 61 76 65 41 73 20 46 69 6c 65 4e 61 6d 65 3a 3d 22 74 65 73 74 5f 22 20 26 20 44 6f 63 4e 75 6d 20 26 20 22 2e 64 6f 63 22 } //1 ActiveDocument.SaveAs FileName:="test_" & DocNum & ".doc"
		$a_03_4 = {2e 43 72 65 61 74 65 28 [0-30] 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 69 6e 74 50 72 6f 63 65 73 73 49 44 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}