
rule TrojanDownloader_O97M_Powdow_YK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.YK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 65 65 73 68 6f 70 70 69 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 49 44 33 2f 67 31 2f 39 37 31 30 33 2e 6a 70 67 } //01 00  http://weeshoppi.com/wp-includes/ID3/g1/97103.jpg
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 } //01 00  powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass
		$a_00_2 = {4f 75 74 46 69 6c 65 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 6a 62 6e 73 64 77 6a 2e 65 78 65 } //00 00  OutFile C:\Users\Public\Documents\jbnsdwj.exe
	condition:
		any of ($a_*)
 
}