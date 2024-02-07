
rule TrojanDownloader_O97M_Powdow_PM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 63 6d 64 2e 65 78 65 20 2f 43 } //01 00  = "cmd.exe /C
		$a_01_1 = {3d 20 22 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70 73 3a 2f 2f 6d 6f 76 65 74 6f 6c 69 67 68 74 2e 78 79 7a 3a 34 34 33 2f 64 69 73 63 6f } //01 00  = "DownloadString('https://movetolight.xyz:443/disco
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c } //01 00  = CreateObject("Wscript.Shell
		$a_03_3 = {2e 52 75 6e 20 28 90 02 0a 20 2b 20 90 02 0a 20 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}