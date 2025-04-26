
rule TrojanDropper_O97M_Hancitor_JAP_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JAP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 73 74 65 74 70 74 77 77 6f 28 29 } //1 Sub stetptwwo()
		$a_01_1 = {43 61 6c 6c 20 68 68 68 68 68 } //1 Call hhhhh
		$a_01_2 = {3d 20 22 5c 53 74 61 74 69 63 2e 64 22 } //1 = "\Static.d"
		$a_01_3 = {26 20 6a 73 64 20 26 20 22 6c 22 20 26 20 22 6c 22 20 26 } //1 & jsd & "l" & "l" &
		$a_03_4 = {76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 53 57 5f 53 48 4f 57 4e 4f 52 4d 41 4c 90 0c 02 00 45 6e 64 20 49 66 90 0c 02 00 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}