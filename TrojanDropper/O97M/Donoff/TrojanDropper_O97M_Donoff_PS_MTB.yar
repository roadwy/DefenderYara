
rule TrojanDropper_O97M_Donoff_PS_MTB{
	meta:
		description = "TrojanDropper:O97M/Donoff.PS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 6e 76 6f 69 63 65 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 73 63 72 69 70 74 69 6e 67 2e 66 69 6c 65 73 79 73 74 65 6d 6f 62 6a 65 63 74 22 29 } //1 invoice = CreateObject("scripting.filesystemobject")
		$a_03_1 = {73 74 72 73 61 76 65 74 6f 20 3d 20 69 6e 76 6f 69 63 65 20 26 20 22 90 05 28 06 61 2d 7a 30 2d 39 2e 6a 73 22 } //1
		$a_03_2 = {73 74 72 6c 69 6e 6b 20 3d 20 22 68 74 74 70 73 3a 2f 2f [0-14] 2e 63 6f 6d 2f [0-09] 2e 70 68 70 22 } //1
		$a_01_3 = {53 65 74 20 6f 62 6a 68 74 74 70 69 6e 76 6f 69 63 65 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 6d 73 78 6d 6c 32 2e 78 6d 6c 68 74 74 70 22 29 } //1 Set objhttpinvoice = CreateObject("msxml2.xmlhttp")
		$a_01_4 = {6f 62 6a 68 74 74 70 69 6e 76 6f 69 63 65 2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 73 74 72 6c 69 6e 6b 2c 20 46 61 6c 73 65 } //1 objhttpinvoice.Open "get", strlink, False
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}