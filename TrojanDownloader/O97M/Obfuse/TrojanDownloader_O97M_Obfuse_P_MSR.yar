
rule TrojanDownloader_O97M_Obfuse_P_MSR{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.P!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 5c 22 20 26 20 52 6e 64 20 26 20 22 2e 6a 73 65 } //01 00  = Environ("USERPROFILE") & "\\" & Rnd & ".jse
		$a_00_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //01 00  = CreateObject("Shell.Application")
		$a_00_2 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 73 6f 6d 65 53 68 65 2c 20 22 22 2c 20 22 43 3a 5c 22 2c 20 22 6f 70 65 6e 22 2c 20 31 } //00 00  .ShellExecute someShe, "", "C:\", "open", 1
	condition:
		any of ($a_*)
 
}