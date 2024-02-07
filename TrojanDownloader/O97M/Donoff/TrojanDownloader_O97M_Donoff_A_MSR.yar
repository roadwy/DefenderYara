
rule TrojanDownloader_O97M_Donoff_A_MSR{
	meta:
		description = "TrojanDownloader:O97M/Donoff.A!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 70 77 74 72 69 63 6b 20 3d 20 4e 65 77 20 57 73 68 53 68 65 6c 6c } //01 00  Set pwtrick = New WshShell
		$a_00_1 = {53 65 74 20 61 20 3d 20 61 70 6c 64 77 69 6e 65 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 43 3a 5c 54 72 61 73 65 5c 64 65 63 6c 61 72 70 61 69 6e 74 62 6c 6f 77 2e 76 62 65 22 2c 20 54 72 75 65 29 } //01 00  Set a = apldwine.CreateTextFile("C:\Trase\declarpaintblow.vbe", True)
		$a_00_2 = {61 2e 57 72 69 74 65 4c 69 6e 65 20 28 61 70 64 6f 2e 61 70 6f 73 6c 63 6b 61 29 } //01 00  a.WriteLine (apdo.aposlcka)
		$a_00_3 = {70 77 74 72 69 63 6b 2e 45 78 65 63 20 22 65 78 70 6c 6f 72 65 72 20 43 3a 5c 54 72 61 73 65 5c 64 65 63 6c 61 72 70 61 69 6e 74 62 6c 6f 77 2e 76 62 65 22 } //01 00  pwtrick.Exec "explorer C:\Trase\declarpaintblow.vbe"
		$a_00_4 = {61 70 6c 64 77 69 6e 65 2e 43 72 65 61 74 65 46 6f 6c 64 65 72 20 28 22 43 3a 5c 54 72 61 73 65 5c 47 72 65 61 74 22 29 } //00 00  apldwine.CreateFolder ("C:\Trase\Great")
		$a_00_5 = {e7 93 00 } //00 00 
	condition:
		any of ($a_*)
 
}