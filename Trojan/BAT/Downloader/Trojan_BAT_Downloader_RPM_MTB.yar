
rule Trojan_BAT_Downloader_RPM_MTB{
	meta:
		description = "Trojan:BAT/Downloader.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //01 00  cdn.discordapp.com
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_2 = {52 00 75 00 6e 00 50 00 45 00 2e 00 52 00 75 00 6e 00 50 00 45 00 } //01 00  RunPE.RunPE
		$a_01_3 = {52 00 75 00 6e 00 50 00 45 00 2e 00 64 00 6c 00 6c 00 } //01 00  RunPE.dll
		$a_01_4 = {70 00 64 00 66 00 2e 00 65 00 78 00 65 00 } //01 00  pdf.exe
		$a_01_5 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Downloader_RPM_MTB_2{
	meta:
		description = "Trojan:BAT/Downloader.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 90 02 80 2e 00 6a 00 70 00 67 00 90 00 } //01 00 
		$a_01_1 = {47 65 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 56 61 72 69 61 62 6c 65 } //01 00  GetEnvironmentVariable
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_3 = {57 65 62 43 6c 69 65 6e 74 } //01 00  WebClient
		$a_01_4 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //01 00  get_Assembly
		$a_01_5 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //01 00  LoadLibrary
		$a_01_6 = {53 68 65 6c 6c } //01 00  Shell
		$a_01_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}