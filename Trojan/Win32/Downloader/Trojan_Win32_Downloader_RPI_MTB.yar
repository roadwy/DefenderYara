
rule Trojan_Win32_Downloader_RPI_MTB{
	meta:
		description = "Trojan:Win32/Downloader.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 00 69 00 73 00 63 00 6f 00 72 00 64 00 2e 00 67 00 67 00 2f 00 59 00 38 00 38 00 67 00 51 00 35 00 65 00 39 00 70 00 78 00 } //01 00  discord.gg/Y88gQ5e9px
		$a_01_1 = {53 69 74 69 63 6f 6e 65 } //01 00  Siticone
		$a_01_2 = {56 00 45 00 53 00 54 00 49 00 47 00 45 00 20 00 4c 00 4f 00 47 00 49 00 4e 00 } //01 00  VESTIGE LOGIN
		$a_01_3 = {41 00 55 00 54 00 48 00 47 00 47 00 2e 00 64 00 6c 00 6c 00 } //01 00  AUTHGG.dll
		$a_01_4 = {55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //01 00  UseShellExecute
		$a_01_5 = {43 72 65 61 74 65 4e 6f 57 69 6e 64 6f 77 } //01 00  CreateNoWindow
		$a_01_6 = {52 00 75 00 6e 00 50 00 45 00 2e 00 64 00 6c 00 6c 00 } //00 00  RunPE.dll
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Downloader_RPI_MTB_2{
	meta:
		description = "Trojan:Win32/Downloader.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 90 02 80 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_01_1 = {53 00 74 00 75 00 62 00 2e 00 65 00 78 00 65 00 } //01 00  Stub.exe
		$a_01_2 = {47 00 65 00 74 00 45 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 6d 00 65 00 6e 00 74 00 56 00 61 00 72 00 69 00 61 00 62 00 6c 00 65 00 } //01 00  GetEnvironmentVariable
		$a_01_3 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_4 = {54 68 72 65 61 64 } //01 00  Thread
		$a_01_5 = {57 65 62 43 6c 69 65 6e 74 } //01 00  WebClient
		$a_01_6 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //00 00  DownloadFile
	condition:
		any of ($a_*)
 
}