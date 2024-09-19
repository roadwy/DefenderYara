
rule Virus_Linux_Marker_RVA_MTB{
	meta:
		description = "Virus:Linux/Marker.RVA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 69 6e 67 73 65 74 78 35 3d 61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 2e 76 62 70 72 6f 6a 65 63 74 2e 76 62 63 6f 6d 70 6f 6e 65 6e 74 73 2e 69 74 65 6d 28 31 29 73 65 74 78 36 3d 6e 6f 72 6d 61 6c 74 65 6d 70 6c 61 74 65 2e 76 62 70 72 6f 6a 65 63 74 2e 76 62 63 6f 6d 70 6f 6e 65 6e 74 73 2e 69 74 65 6d 28 31 29 78 33 3d 78 35 2e 63 6f 64 65 6d 6f 64 75 6c 65 2e 66 69 6e 64 28 78 31 35 2c 31 2c 31 2c 31 30 30 30 30 2c 31 30 30 30 30 29 } //1 document_open()ingsetx5=activedocument.vbproject.vbcomponents.item(1)setx6=normaltemplate.vbproject.vbcomponents.item(1)x3=x5.codemodule.find(x15,1,1,10000,10000)
		$a_01_1 = {77 69 74 68 6f 70 74 69 6f 6e 73 3a 2e 63 6f 6e 66 69 72 6d 63 6f 6e 76 65 72 73 69 6f 6e 73 3d 30 3a 2e 76 69 72 75 73 70 72 6f 74 65 63 74 69 6f 6e 3d 30 3a 2e 73 61 76 65 6e 6f 72 6d 61 6c 70 72 6f 6d 70 74 3d 30 } //1 withoptions:.confirmconversions=0:.virusprotection=0:.savenormalprompt=0
		$a_01_2 = {64 6f 63 75 6d 65 6e 74 5f 63 6c 6f 73 65 28 29 6f 6e 65 72 72 6f 72 72 65 73 75 6d 65 6e 65 78 74 73 65 74 78 35 3d 61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 2e 76 62 70 72 6f 6a 65 63 74 2e 76 62 63 6f 6d 70 6f 6e 65 6e 74 73 2e 69 74 65 6d 28 31 29 73 65 74 78 36 3d 6e 6f 72 6d 61 6c 74 65 6d 70 6c 61 74 65 2e 76 62 70 72 6f 6a 65 63 74 2e 76 62 63 6f 6d 70 6f 6e 65 6e 74 73 2e 69 74 65 6d 28 31 29 78 33 3d 78 35 2e 63 6f 64 65 6d 6f 64 75 6c 65 2e 66 69 6e 64 28 } //1 document_close()onerrorresumenextsetx5=activedocument.vbproject.vbcomponents.item(1)setx6=normaltemplate.vbproject.vbcomponents.item(1)x3=x5.codemodule.find(
		$a_01_3 = {78 35 2e 63 6f 64 65 6d 6f 64 75 6c 65 2e 63 6f 75 6e 74 6f 66 6c 69 6e 65 73 65 6e 64 69 66 78 39 3d 6e 6f 77 28 29 78 37 3d 64 61 79 28 78 39 29 78 38 3d 6d 6f 6e 74 68 28 78 39 29 } //1 x5.codemodule.countoflinesendifx9=now()x7=day(x9)x8=month(x9)
		$a_01_4 = {22 79 6f 75 61 72 65 68 65 61 72 74 6c 65 73 73 2e 22 26 76 62 63 72 6c 66 26 22 79 6f 75 77 69 6c 6c 62 65 70 75 6e 69 73 68 65 64 66 6f 72 74 68 69 73 22 2c } //1 "youareheartless."&vbcrlf&"youwillbepunishedforthis",
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}