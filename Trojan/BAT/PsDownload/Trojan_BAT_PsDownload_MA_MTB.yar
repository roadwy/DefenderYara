
rule Trojan_BAT_PsDownload_MA_MTB{
	meta:
		description = "Trojan:BAT/PsDownload.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 07 16 07 8e 69 6f 90 01 03 0a 13 05 09 6f 90 01 03 0a 00 28 90 01 03 0a 11 05 6f 90 01 03 0a 13 07 2b 00 11 07 2a 90 00 } //5
		$a_01_1 = {45 45 2d 39 31 32 52 65 62 6f 6f 74 52 65 6d 69 6e 64 65 72 2e 73 63 72 69 70 74 2e 70 73 31 } //1 EE-912RebootReminder.script.ps1
		$a_01_2 = {57 72 69 74 65 52 65 73 6f 75 72 63 65 54 6f 46 69 6c 65 } //1 WriteResourceToFile
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}
rule Trojan_BAT_PsDownload_MA_MTB_2{
	meta:
		description = "Trojan:BAT/PsDownload.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {3a 00 2f 00 2f 00 78 00 2e 00 72 00 75 00 6e 00 65 00 2d 00 73 00 70 00 65 00 63 00 74 00 72 00 61 00 6c 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 74 00 6f 00 72 00 72 00 65 00 6e 00 74 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 } //5 ://x.rune-spectrals.com/torrent/uploads/
		$a_01_1 = {4f 74 63 73 65 69 2e 50 72 6f 70 65 72 74 69 65 73 } //2 Otcsei.Properties
		$a_01_2 = {47 77 72 70 75 73 6a 74 6a } //2 Gwrpusjtj
		$a_01_3 = {38 33 36 63 34 65 65 30 2d 38 34 39 65 2d 34 30 30 65 2d 61 63 37 37 2d 64 62 38 35 64 64 63 65 32 32 31 66 } //2 836c4ee0-849e-400e-ac77-db85ddce221f
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=12
 
}
rule Trojan_BAT_PsDownload_MA_MTB_3{
	meta:
		description = "Trojan:BAT/PsDownload.MA!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 6f 77 65 72 73 68 65 6c 6c 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 55 6e 72 65 73 74 72 69 63 74 65 64 20 2d 43 6f 6d 6d 61 6e 64 20 22 49 6e 76 6f 6b 65 2d 57 65 62 72 65 71 75 65 73 74 20 27 68 74 74 70 3a 2f 2f 31 32 34 2e 31 30 36 2e 31 39 37 2e 31 36 37 } //1 Powershell -ExecutionPolicy Unrestricted -Command "Invoke-Webrequest 'http://124.106.197.167
		$a_01_1 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 27 43 3a 5c 50 65 72 66 4c 6f 67 73 27 } //1 Add-MpPreference -ExclusionPath 'C:\PerfLogs'
		$a_01_2 = {42 79 70 61 73 73 20 2d 43 6f 6e 66 69 72 6d 3a 24 66 61 6c 73 65 20 2d 46 6f 72 63 65 } //1 Bypass -Confirm:$false -Force
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}