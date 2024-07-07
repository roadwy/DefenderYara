
rule TrojanDropper_O97M_Hancitor_HAV_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.HAV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {57 30 72 64 2e 64 6c 6c } //1 W0rd.dll
		$a_01_1 = {53 75 62 20 68 69 28 6d 79 68 6f 6d 65 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub hi(myhome As String)
		$a_01_2 = {44 69 6d 20 67 6c 6f 67 20 41 73 20 53 74 72 69 6e 67 } //1 Dim glog As String
		$a_01_3 = {67 6c 6f 67 20 3d 20 72 65 70 69 64 } //1 glog = repid
		$a_01_4 = {44 69 6d 20 68 73 61 20 41 73 20 53 74 72 69 6e 67 } //1 Dim hsa As String
		$a_01_5 = {68 73 61 20 3d 20 67 6c 6f 67 20 26 20 22 5c 57 30 72 64 2e 64 6c 6c 22 } //1 hsa = glog & "\W0rd.dll"
		$a_01_6 = {43 61 6c 6c 20 6a 6f 70 28 6d 79 68 6f 6d 65 2c 20 68 73 61 29 } //1 Call jop(myhome, hsa)
		$a_01_7 = {53 75 62 20 6a 6f 70 28 75 75 75 20 41 73 20 53 74 72 69 6e 67 2c 20 61 61 61 61 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub jop(uuu As String, aaaa As String)
		$a_01_8 = {43 61 6c 6c 20 72 6e 65 65 28 75 75 75 2c 20 61 61 61 61 29 } //1 Call rnee(uuu, aaaa)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}