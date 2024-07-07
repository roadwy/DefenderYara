
rule TrojanDropper_O97M_Hancitor_EOBC_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOBC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 66 66 66 66 20 3d 20 22 67 6c 22 20 26 20 22 69 62 2e 62 22 20 26 20 22 61 78 22 } //1 fffff = "gl" & "ib.b" & "ax"
		$a_01_1 = {6f 78 6c 20 3d 20 22 5c 67 6c 22 20 26 20 22 69 62 2e 64 22 20 26 20 22 6f 22 20 26 20 22 63 22 } //1 oxl = "\gl" & "ib.d" & "o" & "c"
		$a_01_2 = {46 6f 72 20 45 61 63 68 20 4e 65 64 63 20 49 6e 20 6d 64 73 2e 53 75 62 46 6f 6c 64 65 72 73 } //1 For Each Nedc In mds.SubFolders
		$a_01_3 = {43 61 6c 6c 20 6f 75 73 78 } //1 Call ousx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}