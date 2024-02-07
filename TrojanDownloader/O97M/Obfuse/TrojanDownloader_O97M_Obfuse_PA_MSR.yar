
rule TrojanDownloader_O97M_Obfuse_PA_MSR{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PA!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 4a 6e 52 75 79 38 20 26 20 22 52 75 22 20 26 20 4a 6e 52 75 79 38 20 26 20 22 6e } //01 00  = JnRuy8 & "Ru" & JnRuy8 & "n
		$a_01_1 = {3d 20 4a 6e 52 75 79 38 20 26 20 22 53 68 22 20 26 20 4a 6e 52 75 79 38 20 26 20 22 65 6c 22 20 26 20 4a 6e 52 75 79 38 20 26 20 22 6c } //01 00  = JnRuy8 & "Sh" & JnRuy8 & "el" & JnRuy8 & "l
		$a_01_2 = {3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 26 20 22 5c 2e 2e 22 20 26 20 22 5c 2e 2e 5c 22 20 26 20 22 52 65 64 63 6f 22 20 26 20 31 20 26 20 4a 6e 52 75 79 38 20 26 20 22 2e 62 6c 61 68 } //01 00  = Application.StartupPath & "\.." & "\..\" & "Redco" & 1 & JnRuy8 & ".blah
		$a_01_3 = {3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 2c 20 22 43 72 65 61 74 65 54 22 20 26 20 4a 6e 52 75 79 38 20 26 20 22 65 78 74 46 69 6c 65 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 49 6b 6f 6c 74 67 69 29 } //00 00  = CallByName(CreateObject("Scripting.FileSystemObject"), "CreateT" & JnRuy8 & "extFile", VbMethod, Ikoltgi)
	condition:
		any of ($a_*)
 
}