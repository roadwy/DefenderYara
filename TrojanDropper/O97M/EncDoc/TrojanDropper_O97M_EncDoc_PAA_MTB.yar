
rule TrojanDropper_O97M_EncDoc_PAA_MTB{
	meta:
		description = "TrojanDropper:O97M/EncDoc.PAA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {37 35 65 22 22 22 [0-ff] 25 75 73 65 72 70 72 6f 66 69 6c 65 25 5c 64 6f 77 6e 6c 6f 61 64 73 5c 2a 2e 63 72 64 6f 77 6e 6c 6f 61 64 } //1
		$a_01_1 = {6e 65 22 3c 21 64 6f 63 74 79 70 65 68 74 6d 6c 3e 3c 68 74 6d 6c 3e 3c 62 6f 64 79 6f 6e 6c 6f 61 64 3d 27 64 6f 63 75 6d 65 6e 74 2e 66 6f 72 6d 73 5b 30 5d 2e 73 75 62 6d 69 74 28 29 27 3e 3c 66 6f 72 6d 61 63 74 69 6f 6e 3d 27 68 74 74 70 73 3a 2f 2f 77 65 62 68 6f 6f 6b 2e 73 69 74 65 2f 35 37 34 34 63 30 32 30 2d 61 38 64 39 2d 34 37 35 35 2d 61 62 66 62 2d 63 64 65 36 63 63 64 34 35 30 61 66 27 6d 65 74 68 6f 64 3d 27 70 6f } //1 ne"<!doctypehtml><html><bodyonload='document.forms[0].submit()'><formaction='https://webhook.site/5744c020-a8d9-4755-abfb-cde6ccd450af'method='po
		$a_01_2 = {6d 65 6e 74 73 65 74 64 6f 63 3d 61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 77 69 74 68 64 6f 63 2e 63 6f 6e 74 65 6e 74 2e 66 6f 6e 74 2e 63 6f 6c 6f 72 3d 77 64 63 6f 6c 6f 72 62 6c 61 63 6b 65 6e 64 77 } //1 mentsetdoc=activedocumentwithdoc.content.font.color=wdcolorblackendw
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}