
rule TrojanDropper_O97M_Hancitor_PAYS_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.PAYS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {4f 70 74 69 6f 6e 73 2e 44 65 66 61 75 6c 74 46 69 6c 65 50 61 74 68 28 77 64 55 73 65 72 54 65 6d 70 6c 61 74 65 73 50 61 74 68 29 } //1 Options.DefaultFilePath(wdUserTemplatesPath)
		$a_01_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 22 70 70 6c 22 29 } //1 Application.Run("ppl")
		$a_01_2 = {4c 65 6e 28 6c 64 73 29 20 3e 20 32 20 54 68 65 6e } //1 Len(lds) > 2 Then
		$a_01_3 = {43 61 6c 6c 20 70 70 70 78 28 66 64 73 20 26 20 22 7a 6f 22 20 26 20 22 72 22 20 26 20 22 6f 22 20 26 20 66 64 73 61 20 26 20 76 73 73 66 73 29 } //1 Call pppx(fds & "zo" & "r" & "o" & fdsa & vssfs)
		$a_01_4 = {43 61 6c 6c 20 53 65 61 72 63 68 28 4d 79 46 53 4f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 61 29 2c 20 6c 64 73 29 } //1 Call Search(MyFSO.GetFolder(asda), lds)
		$a_01_5 = {50 61 73 73 77 6f 72 64 44 6f 63 75 6d 65 6e 74 3a 3d 22 64 6f 79 6f 75 6b 6e 6f 77 74 68 61 74 74 68 65 67 6f 64 73 6f 66 64 65 61 74 68 6f 6e 6c 79 65 61 74 61 70 70 6c 65 73 3f 22 } //1 PasswordDocument:="doyouknowthatthegodsofdeathonlyeatapples?"
		$a_01_6 = {43 61 6c 6c 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 68 64 68 64 64 28 4c 65 66 74 28 75 75 75 75 63 2c 20 6e 74 67 73 29 20 26 20 74 69 6e 69 29 } //1 Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & tini)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}