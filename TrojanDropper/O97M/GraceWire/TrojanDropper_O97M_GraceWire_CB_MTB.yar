
rule TrojanDropper_O97M_GraceWire_CB_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.CB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 49 20 3d 20 54 72 75 65 [0-20] 74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 51 20 3d 20 46 61 6c 73 65 [0-20] 45 6e 64 20 49 66 } //1
		$a_01_1 = {49 66 20 74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 49 20 41 6e 64 20 6a 20 3d 20 43 6f 75 6e 74 20 41 6e 64 20 63 20 3c 3e 20 22 22 22 22 20 54 68 65 6e 20 47 65 74 50 2e 61 72 61 6d 20 3d 20 47 65 74 50 2e 61 72 61 6d 20 26 20 63 } //1 If tooolsetChunkI And j = Count And c <> """" Then GetP.aram = GetP.aram & c
		$a_01_2 = {63 20 3d 20 4d 69 2e 64 24 28 43 6f 6d 6d 61 2e 6e 64 24 2c 20 69 2c 20 31 29 } //1 c = Mi.d$(Comma.nd$, i, 1)
		$a_01_3 = {46 6f 72 20 69 20 3d 20 31 20 54 6f 20 4c 65 6e 28 43 6f 6d 6d 61 2e 6e 64 24 29 } //1 For i = 1 To Len(Comma.nd$)
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}