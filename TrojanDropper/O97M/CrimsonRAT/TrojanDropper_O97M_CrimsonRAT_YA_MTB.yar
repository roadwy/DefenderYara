
rule TrojanDropper_O97M_CrimsonRAT_YA_MTB{
	meta:
		description = "TrojanDropper:O97M/CrimsonRAT.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 68 65 6c 6c 20 70 61 74 68 5f 4e 61 76 61 5f 66 69 6c 65 20 26 20 22 78 65 22 } //1 Shell path_Nava_file & "xe"
		$a_00_1 = {66 6c 64 72 5f 4e 61 76 61 5f 6e 61 6d 65 20 3d 20 45 6e 76 69 72 6f 6e 24 28 22 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 22 29 } //1 fldr_Nava_name = Environ$("ALLUSERSPROFILE")
		$a_00_2 = {4f 70 65 6e 20 70 61 74 68 5f 4e 61 76 61 5f 66 69 6c 65 20 26 20 22 78 65 22 20 46 6f 72 20 42 69 6e 61 72 79 20 41 63 63 65 73 73 20 57 72 69 74 65 } //1 Open path_Nava_file & "xe" For Binary Access Write
		$a_00_3 = {62 74 73 53 6f 63 64 61 37 28 6c 69 6e 4e 61 76 61 29 20 3d 20 43 42 79 74 65 28 76 6c 29 } //1 btsSocda7(linNava) = CByte(vl)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}