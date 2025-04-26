
rule TrojanDropper_O97M_Hancitor_RVC_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.RVC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 70 74 69 6f 6e 73 2e 44 65 66 61 75 6c 74 46 69 6c 65 50 61 74 68 28 77 64 55 73 65 72 54 65 6d 70 6c 61 74 65 73 50 61 74 68 29 20 26 20 22 5c 69 66 66 22 20 26 20 22 2e 62 69 6e 22 } //1 Options.DefaultFilePath(wdUserTemplatesPath) & "\iff" & ".bin"
		$a_01_1 = {44 6f 63 75 6d 65 6e 74 73 2e 4f 70 65 6e 20 66 69 6c 65 4e 61 6d 65 3a 3d 76 78 63 20 26 20 22 68 65 6c 70 2e 64 22 20 26 20 22 6f 63 22 2c 20 50 61 73 73 77 6f 72 64 44 6f 63 75 6d 65 6e 74 3a 3d 22 64 6f 6e 74 74 6f 75 63 68 6d 65 22 } //1 Documents.Open fileName:=vxc & "help.d" & "oc", PasswordDocument:="donttouchme"
		$a_01_2 = {3d 20 76 78 63 20 26 20 22 66 72 6f 6c 6f 6c 30 2e 72 75 2f 22 } //1 = vxc & "frolol0.ru/"
		$a_01_3 = {44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 0d 0a 43 61 6c 6c 20 6f 6f 61 73 70 70 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}