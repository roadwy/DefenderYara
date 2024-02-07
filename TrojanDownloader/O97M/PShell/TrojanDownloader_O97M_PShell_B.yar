
rule TrojanDownloader_O97M_PShell_B{
	meta:
		description = "TrojanDownloader:O97M/PShell.B,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 45 6e 76 69 72 6f 6e 24 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 5c 41 64 6f 62 65 41 63 72 6f 62 61 74 4c 69 63 65 6e 73 65 56 65 72 69 66 79 2e 70 73 31 22 } //01 00  = Environ$("AppData") & "\AdobeAcrobatLicenseVerify.ps1"
		$a_00_1 = {2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 71 67 63 4c 79 69 43 6b 78 2c 20 32 2c 20 54 72 75 65 29 } //01 00  .OpenTextFile(qgcLyiCkx, 2, True)
		$a_00_2 = {3d 20 45 6e 76 69 72 6f 6e 24 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 5c 41 64 6f 62 65 41 63 72 6f 62 61 74 4c 69 63 65 6e 73 65 56 65 72 69 66 79 2e 76 62 73 22 } //01 00  = Environ$("AppData") & "\AdobeAcrobatLicenseVerify.vbs"
		$a_00_3 = {28 25 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 25 29 20 3a 20 6f 53 68 65 6c 6c 2e 72 75 6e 20 25 63 6d 64 2e 65 78 65 20 2f 63 20 50 6f 77 65 72 73 68 65 6c 6c } //00 00  (%WScript.Shell%) : oShell.run %cmd.exe /c Powershell
	condition:
		any of ($a_*)
 
}