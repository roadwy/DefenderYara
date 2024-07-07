
rule TrojanDropper_O97M_Hancitor_RVA_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.RVA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 CreateObject("Scripting.FileSystemObject")
		$a_01_1 = {4e 61 6d 65 20 6f 6c 6f 6c 6f 77 20 26 20 22 5c 6d 73 22 20 26 20 22 61 6c 73 2e 70 75 6d 70 6c 22 20 41 73 20 70 61 66 68 20 26 20 22 5c 4d 73 4d 70 2e 64 6c 6c 22 } //1 Name ololow & "\ms" & "als.pumpl" As pafh & "\MsMp.dll"
		$a_01_2 = {22 5c 6d 73 22 20 26 20 22 61 6c 73 2e 70 75 6d 70 6c 22 } //1 "\ms" & "als.pumpl"
		$a_01_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 22 6a 6f 70 22 2c 20 6d 79 68 6f 6d 65 2c 20 70 6c 6f 70 20 26 20 22 5c 4d 73 4d 70 2e 64 6c 6c 22 29 } //1 Application.Run("jop", myhome, plop & "\MsMp.dll")
		$a_01_4 = {43 61 6c 6c 20 72 6e 65 65 28 75 75 75 2c 20 61 61 61 61 29 } //1 Call rnee(uuu, aaaa)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}