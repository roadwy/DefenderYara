
rule TrojanDropper_O97M_CobaltStrike_API_MTB{
	meta:
		description = "TrojanDropper:O97M/CobaltStrike.API!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 70 61 72 61 67 72 61 70 68 6f 70 65 6e 64 6c 6c 70 61 74 68 66 6f 72 62 69 6e 61 72 79 61 73 31 70 75 74 31 62 63 6c 6f 73 65 31 } //1 getparagraphopendllpathforbinaryas1put1bclose1
		$a_01_1 = {65 74 64 73 62 61 73 65 36 34 64 65 63 6f 64 65 78 67 6c 77 61 67 78 77 79 78 62 70 6c 6d 72 73 62 61 66 6c 6e 70 62 61 73 65 36 34 64 65 63 6f 64 65 78 67 6e 68 79 32 68 6c 6c 76 68 6b 72 65 35 74 73 6c 64 71 72 6b 68 65 6c 6e 72 74 63 61 } //1 etdsbase64decodexglwagxwyxbplmrsbaflnpbase64decodexgnhy2hllvhkre5tsldqrkhelnrtca
		$a_01_2 = {6e 61 6d 65 66 6e 7a 73 74 61 73 73 74 61 74 62 61 73 65 36 34 64 65 63 6f 64 65 78 65 31 70 79 33 6a 76 63 32 39 6d 64 66 78 75 7a 77 66 74 63 31 78 6a 64 78 6a 79 7a 77 35 30 65 74 64 73 65 6e 64 69 66 65 6e 64 } //1 namefnzstasstatbase64decodexe1py3jvc29mdfxuzwftc1xjdxjyzw50etdsendifend
		$a_01_3 = {67 65 74 77 70 66 6f 72 69 30 74 6f 75 62 6f 75 6e 64 64 64 69 73 74 72 72 65 76 65 72 73 65 64 69 6e 65 78 74 69 73 6a 6f 69 6e 64 67 65 74 70 61 72 61 67 72 61 70 68 73 74 72 63 6f 6e 76 62 61 73 65 36 34 64 65 63 6f 64 65 73 76 62 66 72 6f 6d 75 6e 69 63 6f 64 65 65 6e 64 66 75 6e 63 74 69 6f 6e } //1 getwpfori0touboundddistrreversedinextisjoindgetparagraphstrconvbase64decodesvbfromunicodeendfunction
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}