
rule TrojanDropper_O97M_Trickbot_G_MSR{
	meta:
		description = "TrojanDropper:O97M/Trickbot.G!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 70 65 61 6b 2e 57 72 69 74 65 20 46 61 78 49 6e 66 6f 2e 43 69 63 6c 65 73 } //01 00  Speak.Write FaxInfo.Cicles
		$a_01_1 = {45 78 65 63 20 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 43 3a 5c 42 61 74 74 6c 65 5c 54 68 65 6d 65 73 2e 76 62 73 22 } //02 00  Exec "explorer.exe C:\Battle\Themes.vbs"
		$a_03_2 = {4d 73 67 42 6f 78 28 22 44 6f 20 79 6f 75 20 72 65 61 6c 6c 79 20 22 20 5f 90 01 0a 26 20 22 77 61 6e 74 20 74 6f 20 63 6c 6f 73 65 20 74 68 65 20 64 6f 63 75 6d 65 6e 74 3f 22 2c 20 5f 90 01 0a 76 62 59 65 73 4e 6f 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}