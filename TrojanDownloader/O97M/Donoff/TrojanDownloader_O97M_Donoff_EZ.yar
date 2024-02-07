
rule TrojanDownloader_O97M_Donoff_EZ{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EZ,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {2b 20 22 63 22 20 2b 20 22 6d 64 20 2f 56 22 20 2b 20 22 20 2f 43 20 22 20 2b 20 43 68 72 28 33 34 29 20 2b } //01 00  + "c" + "md /V" + " /C " + Chr(34) +
		$a_00_1 = {3d 20 4d 69 64 28 } //01 00  = Mid(
		$a_00_2 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //00 00  Sub AutoOpen()
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_EZ_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EZ,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 55 73 65 72 73 5c 22 20 26 20 45 6e 76 69 72 6f 6e 28 22 55 73 65 72 4e 61 6d 65 22 29 20 26 20 22 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 22 20 26 } //01 00  C:\Users\" & Environ("UserName") & "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" &
		$a_00_1 = {3d 6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 20 26 20 43 68 72 28 33 34 29 20 26 20 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 20 26 20 43 68 72 28 33 34 29 20 26 20 22 29 } //01 00  =new ActiveXObject(" & Chr(34) & "WScript.Shell" & Chr(34) & ")
		$a_00_2 = {2e 72 75 6e 28 27 25 77 69 6e 64 69 72 25 5c 5c 53 79 73 74 65 6d 33 32 5c 5c 63 6d 64 2e 65 78 65 20 2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 6e 6f 70 20 2d 77 20 68 69 64 64 65 6e 20 2d 65 } //00 00  .run('%windir%\\System32\\cmd.exe /c powershell.exe -nop -w hidden -e
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_EZ_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EZ,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 22 70 6f 77 65 22 20 2b 20 22 72 73 68 65 6c 6c 20 24 90 02 10 20 3d 20 6e 65 22 20 2b 20 22 77 2d 6f 62 22 20 2b 20 22 6a 65 63 74 20 53 79 73 22 20 2b 20 22 74 65 6d 2e 4e 65 22 20 2b 20 22 74 2e 57 65 62 22 20 2b 20 22 43 6c 69 65 6e 74 3b 24 90 02 10 20 3d 20 6e 65 77 2d 6f 62 22 20 2b 20 22 6a 65 63 74 20 72 61 22 20 2b 20 22 6e 64 6f 6d 3b 20 20 22 90 00 } //01 00 
		$a_03_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 90 02 20 20 2b 20 90 02 20 2c 20 30 90 00 } //01 00 
		$a_03_2 = {3d 20 22 70 6f 22 20 2b 20 22 77 65 72 73 68 65 22 20 2b 20 22 6c 6c 20 24 90 02 10 20 3d 20 6e 65 77 2d 6f 62 22 20 2b 20 22 6a 65 63 74 20 53 79 73 22 20 2b 20 22 74 65 6d 2e 4e 65 22 20 2b 20 22 74 2e 57 65 62 22 20 2b 20 22 43 6c 69 22 20 2b 20 22 65 6e 74 3b 24 90 02 10 20 3d 20 6e 65 77 2d 6f 62 22 20 2b 20 22 6a 65 63 74 20 72 61 22 20 2b 20 22 6e 64 6f 6d 3b 20 20 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}