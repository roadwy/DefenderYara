
rule TrojanDropper_O97M_GraceWire_D_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.D!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2b 20 22 2e 64 22 20 2b 20 22 6c 6c 22 } //1 + ".d" + "ll"
		$a_01_1 = {4b 69 6c 6c 41 72 72 61 79 20 5a 69 70 46 6f 6c 64 65 72 20 26 } //1 KillArray ZipFolder &
		$a_01_2 = {6f 75 74 66 70 20 3d 20 6c 4f 2e 70 65 6e 28 22 6f 75 74 70 75 74 2e 72 61 77 22 2c 20 31 29 } //1 outfp = lO.pen("output.raw", 1)
		$a_03_3 = {2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 55 73 65 72 46 6f 72 6d 90 01 01 2e 54 65 78 74 42 6f 78 90 01 01 2e 54 61 67 29 90 00 } //1
		$a_01_4 = {26 20 22 2e 20 22 20 26 20 5f } //1 & ". " & _
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}