
rule TrojanDropper_O97M_Obfuse_BKSY_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.BKSY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 65 66 74 28 75 75 75 75 63 2c 20 6e 74 67 73 29 20 26 20 22 4c 6f 63 61 6c 5c 22 20 26 20 69 6f 78 20 26 20 22 65 6d 70 22 2c 20 76 62 44 69 72 65 63 74 6f 72 79 29 20 3d 20 22 22 20 54 68 65 6e } //1 Left(uuuuc, ntgs) & "Local\" & iox & "emp", vbDirectory) = "" Then
		$a_01_1 = {43 61 6c 6c 20 50 72 69 6d 65 72 31 28 46 6f 6c 64 65 72 20 26 20 22 5c 22 20 26 20 66 31 2e 4e 61 6d 65 20 26 20 22 5c 22 29 } //1 Call Primer1(Folder & "\" & f1.Name & "\")
		$a_01_2 = {6a 76 63 20 3d 20 64 64 64 20 26 20 22 5c 7a 6f 72 6f 2e 64 6f 63 22 } //1 jvc = ddd & "\zoro.doc"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}