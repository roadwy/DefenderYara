
rule TrojanDropper_O97M_Commprs_YA_MTB{
	meta:
		description = "TrojanDropper:O97M/Commprs.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 6e 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 } //1 In ActiveDocument.BuiltInDocumentProperties
		$a_01_1 = {53 68 65 6c 6c 20 28 } //1 Shell (
		$a_01_2 = {2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 } //1 .FileSystemObject
		$a_01_3 = {41 73 20 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 79 } //1 As DocumentProperty
		$a_01_4 = {2e 4e 61 6d 65 20 3d 20 22 43 6f 6d 6d 65 6e 74 73 22 } //1 .Name = "Comments"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}