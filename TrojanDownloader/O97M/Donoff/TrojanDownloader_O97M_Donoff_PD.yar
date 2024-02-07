
rule TrojanDownloader_O97M_Donoff_PD{
	meta:
		description = "TrojanDownloader:O97M/Donoff.PD,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 52 69 67 68 74 28 22 49 6e 20 73 69 64 65 20 77 65 20 67 6f 6e 6e 61 20 73 65 65 20 52 65 65 56 65 44 57 53 63 72 69 70 74 22 2c 20 37 29 20 26 20 22 2e 22 20 26 20 4c 65 66 74 28 22 53 68 65 6c 6c 69 6e 73 68 61 6c 61 22 2c 20 35 29 } //01 00  = Right("In side we gonna see ReeVeDWScript", 7) & "." & Left("Shellinshala", 5)
		$a_00_1 = {56 42 41 2e 43 61 6c 6c 42 79 4e 61 6d 65 20 4a 65 72 6b 2c 20 22 52 55 4e 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 6d 6f 6e 69 6b 65 72 2c 20 47 61 74 73 } //01 00  VBA.CallByName Jerk, "RUN", VbMethod, moniker, Gats
		$a_00_2 = {3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 54 65 78 74 } //01 00  = ThisDocument.Content.Text
		$a_00_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 26 20 22 5c 73 22 20 26 20 22 65 2e 22 20 26 20 43 68 72 28 31 31 30 20 2d 20 32 20 2d 20 32 29 20 26 20 22 73 65 } //00 00  Application.StartupPath & "\s" & "e." & Chr(110 - 2 - 2) & "se
	condition:
		any of ($a_*)
 
}