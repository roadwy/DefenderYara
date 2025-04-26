
rule TrojanDropper_O97M_GraceWire_DJ_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.DJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {46 6f 72 20 69 20 3d 20 31 20 54 6f 20 4c 65 6e 28 43 6f 6d 6d 61 2e 6e 64 24 29 } //1 For i = 1 To Len(Comma.nd$)
		$a_01_1 = {43 20 3d 20 4d 69 2e 64 24 28 43 6f 6d 6d 61 2e 6e 64 24 2c 20 69 2c 20 31 29 } //1 C = Mi.d$(Comma.nd$, i, 1)
		$a_01_2 = {49 66 20 74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 49 20 41 6e 64 20 6a 20 3d 20 43 6f 75 6e 74 20 41 6e 64 20 43 20 3c 3e 20 22 22 22 22 20 54 68 65 6e 20 47 65 74 50 2e 61 72 61 6d 20 3d 20 47 65 74 50 2e 61 72 61 6d 20 26 20 43 } //1 If tooolsetChunkI And j = Count And C <> """" Then GetP.aram = GetP.aram & C
		$a_01_3 = {74 6d 70 53 74 72 20 3d 20 74 6d 70 53 74 72 20 26 20 22 5c 22 20 26 20 74 6d 70 28 69 29 } //1 tmpStr = tmpStr & "\" & tmp(i)
		$a_01_4 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 52 65 64 42 75 74 74 6f 6e 28 64 49 6d 6d 65 72 20 41 73 20 44 6f 75 62 6c 65 29 } //1 Public Function RedButton(dImmer As Double)
		$a_01_5 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 56 6f 6f 6f 6f 6f 68 65 61 64 28 29 } //1 Public Function Vooooohead()
		$a_01_6 = {73 20 3d 20 63 61 72 2e 43 68 65 63 6b 43 61 72 } //1 s = car.CheckCar
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}