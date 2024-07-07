
rule Trojan_O97M_Remcos_BIK_MTB{
	meta:
		description = "Trojan:O97M/Remcos.BIK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 61 6d 73 6c 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 4f 73 6b 66 5a 55 57 68 28 29 29 } //1 Set amsl = GetObject(OskfZUWh())
		$a_01_1 = {61 6d 73 6c 2e 52 75 6e 20 22 50 22 20 2b 20 6d 4a 4a 47 4d 28 66 67 66 6a 68 66 67 66 67 29 2c 20 30 } //1 amsl.Run "P" + mJJGM(fgfjhfgfg), 0
		$a_01_2 = {3d 20 6d 4a 4a 47 4d 28 22 42 30 41 38 35 44 46 34 30 22 20 2b 20 66 6a 6a 73 64 66 68 6c 28 29 20 2b 20 6a 30 30 66 66 64 67 64 66 28 29 20 2b 20 74 74 65 72 37 66 64 67 30 28 29 } //1 = mJJGM("B0A85DF40" + fjjsdfhl() + j00ffdgdf() + tter7fdg0()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_O97M_Remcos_BIK_MTB_2{
	meta:
		description = "Trojan:O97M/Remcos.BIK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 73 73 73 73 73 73 73 28 22 61 22 2c 20 65 4e 59 4c 53 6b 4c 6e 43 47 47 70 73 53 48 29 } //1 = sssssss("a", eNYLSkLnCGGpsSH)
		$a_01_1 = {3d 20 56 61 6c 28 22 26 48 22 20 26 20 28 4d 69 64 24 28 44 61 74 61 49 6e 2c 20 28 32 20 2a 20 6c 6f 6e 44 61 74 61 50 74 72 29 20 2d 20 31 2c 20 32 29 29 29 } //1 = Val("&H" & (Mid$(DataIn, (2 * lonDataPtr) - 1, 2)))
		$a_01_2 = {3d 20 41 73 63 28 4d 69 64 24 28 43 6f 64 65 4b 65 79 2c 20 28 28 6c 6f 6e 44 61 74 61 50 74 72 20 4d 6f 64 20 4c 65 6e 28 43 6f 64 65 4b 65 79 29 29 20 2b 20 31 29 2c 20 31 29 29 } //1 = Asc(Mid$(CodeKey, ((lonDataPtr Mod Len(CodeKey)) + 1), 1))
		$a_01_3 = {3d 20 53 68 65 6c 6c 28 73 73 73 73 73 73 73 29 } //1 = Shell(sssssss)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}