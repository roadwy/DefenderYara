
rule TrojanDropper_O97M_Hancitor_JOBD_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JOBD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 64 73 73 64 66 28 29 90 0c 02 00 43 61 6c 6c 20 6d 6d 28 22 68 22 20 26 20 22 74 22 20 26 20 22 74 22 29 90 0c 02 00 45 6e 64 20 53 75 62 } //1
		$a_03_1 = {43 61 6c 6c 20 6b 6d 90 0c 02 00 44 6f 63 75 6d 65 6e 74 73 2e 4f 70 65 6e 20 66 69 6c 65 4e 61 6d 65 3a 3d 76 78 63 20 26 20 22 68 65 6c 22 20 26 20 76 76 2c 20 50 61 73 73 77 6f 72 64 44 6f 63 75 6d 65 6e 74 3a 3d 22 34 34 } //1
		$a_01_2 = {53 75 62 20 6d 6d 28 6a 6a 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub mm(jj As String)
		$a_01_3 = {62 63 62 64 66 20 3d 20 62 63 62 64 66 20 26 20 6a 6a } //1 bcbdf = bcbdf & jj
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}