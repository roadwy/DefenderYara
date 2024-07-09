
rule TrojanDropper_O97M_Hancitor_SS_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 6d 69 6b 6f 28 62 63 62 64 66 2c 20 22 64 22 20 26 20 22 6f 22 20 26 20 22 63 22 29 } //1 Call miko(bcbdf, "d" & "o" & "c")
		$a_01_1 = {43 61 6c 6c 20 6d 6d 28 22 74 72 6f 70 69 74 72 6f 6e 35 2e 72 22 20 26 20 22 75 2f 22 29 } //1 Call mm("tropitron5.r" & "u/")
		$a_01_2 = {28 75 75 20 26 20 22 5c 69 66 66 22 20 26 20 70 6c 66 20 26 20 22 62 22 20 26 20 22 69 6e 22 2c 20 76 62 44 69 72 65 63 74 6f 72 79 29 } //1 (uu & "\iff" & plf & "b" & "in", vbDirectory)
		$a_01_3 = {44 6f 63 75 6d 65 6e 74 73 2e 4f 70 65 6e 20 66 69 6c 65 4e 61 6d 65 3a 3d 76 78 63 20 26 20 22 68 65 6c 22 20 26 20 76 76 } //1 Documents.Open fileName:=vxc & "hel" & vv
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDropper_O97M_Hancitor_SS_MTB_2{
	meta:
		description = "TrojanDropper:O97M/Hancitor.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 6d 6d 28 22 [0-0f] 2e 72 22 20 26 20 22 75 2f 22 29 } //1
		$a_01_1 = {44 6f 63 75 6d 65 6e 74 73 2e 4f 70 65 6e 20 66 69 6c 65 4e 61 6d 65 3a 3d 76 78 63 20 26 20 22 68 65 6c 22 20 26 20 76 76 } //1 Documents.Open fileName:=vxc & "hel" & vv
		$a_01_2 = {49 66 20 44 69 72 28 75 75 20 26 20 22 5c 69 66 66 22 20 26 20 70 6c 66 20 26 20 22 62 22 20 26 20 22 69 22 20 26 20 22 6e 22 2c 20 76 62 44 69 72 65 63 74 6f 72 79 29 20 3d 20 22 22 20 54 68 65 6e } //1 If Dir(uu & "\iff" & plf & "b" & "i" & "n", vbDirectory) = "" Then
		$a_01_3 = {43 61 6c 6c 20 6d 69 6b 6f 28 62 63 62 64 66 2c 20 22 64 22 20 26 20 22 6f 22 20 26 20 22 63 22 29 } //1 Call miko(bcbdf, "d" & "o" & "c")
		$a_01_4 = {43 61 6c 6c 20 6d 6d 28 22 68 22 20 26 20 22 74 22 20 26 20 6b 6c 78 29 } //1 Call mm("h" & "t" & klx)
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}