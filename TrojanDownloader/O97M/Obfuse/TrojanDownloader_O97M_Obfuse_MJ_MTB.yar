
rule TrojanDownloader_O97M_Obfuse_MJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.MJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 65 6c 65 63 74 69 6f 6e 2e 42 6f 72 64 65 72 73 28 78 6c 45 64 67 65 54 6f 70 29 } //1 Selection.Borders(xlEdgeTop)
		$a_01_1 = {78 6c 43 6f 6e 74 69 6e 75 6f 75 73 } //1 xlContinuous
		$a_01_2 = {2e 57 65 69 67 68 74 20 3d 20 78 6c 54 68 69 6e } //1 .Weight = xlThin
		$a_01_3 = {67 65 68 73 65 65 6a 77 68 65 67 64 70 78 63 78 6d 69 69 79 6e 67 71 75 61 7a 7a 62 6d 79 6d 69 75 69 70 62 6e 78 72 77 } //1 gehseejwhegdpxcxmiiyngquazzbmymiuipbnxrw
		$a_01_4 = {64 6f 6b 64 70 76 67 77 74 70 6d 61 66 6e 73 69 70 77 65 7a 6e 70 63 71 7a 74 61 71 70 7a 79 76 71 6f 61 70 78 67 74 77 } //1 dokdpvgwtpmafnsipweznpcqztaqpzyvqoapxgtw
		$a_01_5 = {2e 43 72 65 61 74 65 28 71 79 66 78 79 77 77 6b 72 6a 6a 72 62 79 6f 7a 6f 6e 72 65 65 68 6a 69 73 79 6a 67 69 62 6a 70 71 6c 69 6f 62 74 77 64 29 } //1 .Create(qyfxywwkrjjrbyozonreehjisyjgibjpqliobtwd)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}