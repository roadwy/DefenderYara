
rule TrojanDropper_O97M_GraceWire_DM_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.DM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 4f 66 62 6c 20 3d 20 6f 66 62 6c 20 2b 20 66 6c 61 79 53 74 72 69 6e 67 20 2b 20 22 2e 64 22 20 2b 20 22 6c 6c } //1 sOfbl = ofbl + flayString + ".d" + "ll
		$a_03_1 = {6c 69 71 75 69 64 4f 6e 65 20 3d 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 2b 20 22 5c [0-10] 22 } //1
		$a_01_2 = {6c 69 71 75 69 64 4f 6e 65 20 3d 20 6c 69 71 75 69 64 4f 6e 65 20 2b 20 22 6c 2e 78 6c 73 78 22 } //1 liquidOne = liquidOne + "l.xlsx"
		$a_01_3 = {6f 66 62 6c 20 3d 20 6f 66 62 6c 20 2b 20 22 5c 73 72 74 5f 6a 6f 69 6e 22 } //1 ofbl = ofbl + "\srt_join"
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}