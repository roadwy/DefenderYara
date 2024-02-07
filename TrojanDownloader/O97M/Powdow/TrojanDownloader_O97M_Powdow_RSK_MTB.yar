
rule TrojanDownloader_O97M_Powdow_RSK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RSK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 61 72 61 6d 69 73 63 6f 6e 73 74 72 75 63 74 2e 72 6f 2f 77 70 2d 61 64 6d 69 6e 2f 75 58 2f } //01 00  http://aramisconstruct.ro/wp-admin/uX/
		$a_00_1 = {24 70 61 74 68 3d 27 43 3a 5c 55 73 65 72 73 5c 4b 65 61 6d 61 5c 6f 6e 64 5f 66 69 6c 2e 64 6c 6c 27 } //01 00  $path='C:\Users\Keama\ond_fil.dll'
		$a_00_2 = {73 74 72 43 6f 6d 6d 61 6e 64 20 3d 20 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 6e 6f 65 78 69 74 20 2d 63 6f 6d 6d 61 6e 64 20 22 20 26 20 66 75 6c 6c 53 74 72 69 6e 67 } //01 00  strCommand = "powershell.exe -noexit -command " & fullString
		$a_00_3 = {57 73 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  WsShell = CreateObject("WScript.Shell")
		$a_00_4 = {66 6f 72 65 61 63 68 28 24 56 33 68 45 50 4d 4d 5a 20 69 6e 20 24 75 72 6c 5f 6c 69 73 74 29 7b 74 72 79 7b 24 57 65 62 43 6c 69 65 6e 74 2e 64 6f 77 6e 6c 6f 61 64 66 69 6c 65 28 24 56 33 68 45 50 4d 4d 5a 2c 24 70 61 74 68 29 } //00 00  foreach($V3hEPMMZ in $url_list){try{$WebClient.downloadfile($V3hEPMMZ,$path)
	condition:
		any of ($a_*)
 
}