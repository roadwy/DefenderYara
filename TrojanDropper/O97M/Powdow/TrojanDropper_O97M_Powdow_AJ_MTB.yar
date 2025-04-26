
rule TrojanDropper_O97M_Powdow_AJ_MTB{
	meta:
		description = "TrojanDropper:O97M/Powdow.AJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 20 22 22 20 26 20 [0-12] 20 26 20 45 6d 70 74 79 20 26 20 22 5c [0-14] 22 20 26 20 45 6d 70 74 79 20 26 20 22 2e 6a 22 20 26 20 45 6d 70 74 79 20 26 20 22 73 22 20 26 20 22 22 20 26 20 22 65 22 20 26 20 45 6d 70 74 79 } //1
		$a_01_1 = {50 72 69 6e 74 20 23 4e 74 6f 6f 6b 65 72 2c } //1 Print #Ntooker,
		$a_01_2 = {52 65 70 6c 61 63 65 57 69 74 68 3a 3d 22 22 } //1 ReplaceWith:=""
		$a_01_3 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 63 6f 6e 74 65 6e 74 2e 54 65 78 74 20 3d 20 22 22 } //1 ActiveDocument.content.Text = ""
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}