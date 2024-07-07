
rule TrojanDropper_O97M_Hancitor_DR_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.DR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {75 75 6a 20 3d 20 22 5c 70 6c 75 6d 62 75 73 2e 72 69 6b 22 } //1 uuj = "\plumbus.rik"
		$a_01_1 = {6b 75 72 6c 62 69 6b 20 26 20 22 5c 65 64 67 65 2e 64 22 20 26 20 22 6c 6c 22 29 20 3d 20 22 22 } //1 kurlbik & "\edge.d" & "ll") = ""
		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 22 68 69 22 2c 20 52 6f 6f 74 50 61 74 68 29 } //1 Application.Run("hi", RootPath)
		$a_01_3 = {2e 44 65 66 61 75 6c 74 46 69 6c 65 50 61 74 68 28 77 64 53 74 61 72 74 75 70 50 61 74 68 29 } //1 .DefaultFilePath(wdStartupPath)
		$a_01_4 = {56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 VBA.CreateObject("WScript.Shell")
		$a_01_5 = {2e 52 75 6e 20 62 63 76 73 64 73 66 20 26 20 22 20 22 20 26 20 6f 79 73 } //1 .Run bcvsdsf & " " & oys
		$a_01_6 = {43 61 6c 6c 20 73 74 65 74 70 74 77 77 6f } //1 Call stetptwwo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule TrojanDropper_O97M_Hancitor_DR_MTB_2{
	meta:
		description = "TrojanDropper:O97M/Hancitor.DR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6f 6c 6f 6c 6f 77 20 26 20 22 5c 70 6c 75 6d 62 75 73 2e 72 69 6b 22 20 41 73 20 70 61 66 68 20 26 20 22 5c 22 } //1 ololow & "\plumbus.rik" As pafh & "\"
		$a_01_1 = {4f 70 74 69 6f 6e 73 2e 44 65 66 61 75 6c 74 46 69 6c 65 50 61 74 68 28 77 64 53 74 61 72 74 75 70 50 61 74 68 29 } //1 Options.DefaultFilePath(wdStartupPath)
		$a_01_2 = {69 6f 66 20 26 20 22 2e 22 20 26 20 74 65 72 20 26 20 22 78 65 22 } //1 iof & "." & ter & "xe"
		$a_01_3 = {28 73 66 20 26 20 22 5c 70 6c 75 6d 62 75 73 2e 72 69 6b 22 29 20 3d 20 22 22 } //1 (sf & "\plumbus.rik") = ""
		$a_01_4 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 22 6a 6f 70 22 2c 20 6d 79 68 6f 6d 65 2c 20 70 6c 6f 70 20 26 20 22 5c 77 65 72 6d 67 72 2e 64 6c 6c 22 29 } //1 Application.Run("jop", myhome, plop & "\wermgr.dll")
		$a_01_5 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 22 68 69 22 2c 20 52 6f 6f 74 50 61 74 68 29 } //1 Application.Run("hi", RootPath)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}