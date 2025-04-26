
rule TrojanDropper_O97M_Obfuse_FG_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.FG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 2b 20 22 5c 44 6f 63 75 6d 65 6e 74 73 5c 41 64 6f 62 65 20 48 65 6c 70 20 43 65 6e 74 65 72 22 } //1 Environ("USERPROFILE") + "\Documents\Adobe Help Center"
		$a_01_1 = {2e 46 69 6c 65 45 78 69 73 74 73 28 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 2b 20 22 5c 44 6f 63 75 6d 65 6e 74 73 5c 22 20 2b 20 22 45 75 61 35 38 59 32 46 2e 74 78 74 22 } //1 .FileExists(Environ("USERPROFILE") + "\Documents\" + "Eua58Y2F.txt"
		$a_00_2 = {48 65 6c 70 43 65 6e 74 65 72 55 70 64 61 74 65 72 2e 76 62 73 22 } //1 HelpCenterUpdater.vbs"
		$a_00_3 = {2e 52 75 6e 28 22 77 73 63 72 69 70 74 2e 65 78 65 20 2f 2f 62 20 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 71 73 20 2b 20 43 68 72 28 33 34 29 2c 20 34 2c 20 46 61 6c 73 65 29 } //1 .Run("wscript.exe //b " + Chr(34) + qs + Chr(34), 4, False)
		$a_00_4 = {53 70 6c 69 74 28 73 74 72 2c 20 22 22 72 6d 22 22 2c 20 2d 31 2c 20 30 29 } //1 Split(str, ""rm"", -1, 0)
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}