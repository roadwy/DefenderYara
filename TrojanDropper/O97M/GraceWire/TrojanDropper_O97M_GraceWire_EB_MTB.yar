
rule TrojanDropper_O97M_GraceWire_EB_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.EB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {44 69 6d 20 76 53 70 65 65 64 20 41 73 20 49 6e 74 65 67 65 72 } //1 Dim vSpeed As Integer
		$a_01_1 = {44 69 6d 20 76 4c 69 63 65 6e 73 65 50 6c 61 74 65 20 41 73 20 53 74 72 69 6e 67 } //1 Dim vLicensePlate As String
		$a_01_2 = {63 61 72 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 } //1 car.SpecialFolders
		$a_01_3 = {63 6d 64 5f 63 61 72 69 2e 45 6e 61 62 6c 65 64 20 3d 20 54 72 75 65 } //1 cmd_cari.Enabled = True
		$a_01_4 = {54 42 54 20 3d 20 54 42 54 20 2b 20 22 22 20 2b 20 22 22 } //1 TBT = TBT + "" + ""
		$a_03_5 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 53 70 65 65 64 28 29 20 41 73 20 49 6e 74 65 67 65 72 [0-10] 53 70 65 65 64 20 3d 20 76 53 70 65 65 64 90 0c 02 00 45 6e 64 20 50 72 6f 70 65 72 74 79 } //1
		$a_03_6 = {49 66 20 4c 65 6e 28 6c 70 29 20 3c 3e 20 36 20 54 68 65 6e 20 45 72 72 2e 52 61 69 73 65 20 28 78 6c 45 72 72 56 61 6c 75 65 29 [0-10] 76 4c 69 63 65 6e 73 65 50 6c 61 74 65 20 3d 20 6c 70 90 0c 02 00 45 6e 64 20 50 72 6f 70 65 72 74 79 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}