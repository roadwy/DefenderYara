
rule Trojan_BAT_PsDownload_MA_MTB{
	meta:
		description = "Trojan:BAT/PsDownload.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 07 16 07 8e 69 6f 90 01 03 0a 13 05 09 6f 90 01 03 0a 00 28 90 01 03 0a 11 05 6f 90 01 03 0a 13 07 2b 00 11 07 2a 90 00 } //01 00 
		$a_01_1 = {45 45 2d 39 31 32 52 65 62 6f 6f 74 52 65 6d 69 6e 64 65 72 2e 73 63 72 69 70 74 2e 70 73 31 } //01 00  EE-912RebootReminder.script.ps1
		$a_01_2 = {57 72 69 74 65 52 65 73 6f 75 72 63 65 54 6f 46 69 6c 65 } //01 00  WriteResourceToFile
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00  TransformFinalBlock
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_PsDownload_MA_MTB_2{
	meta:
		description = "Trojan:BAT/PsDownload.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {3a 00 2f 00 2f 00 78 00 2e 00 72 00 75 00 6e 00 65 00 2d 00 73 00 70 00 65 00 63 00 74 00 72 00 61 00 6c 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 74 00 6f 00 72 00 72 00 65 00 6e 00 74 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 } //02 00  ://x.rune-spectrals.com/torrent/uploads/
		$a_01_1 = {4f 74 63 73 65 69 2e 50 72 6f 70 65 72 74 69 65 73 } //02 00  Otcsei.Properties
		$a_01_2 = {47 77 72 70 75 73 6a 74 6a } //02 00  Gwrpusjtj
		$a_01_3 = {38 33 36 63 34 65 65 30 2d 38 34 39 65 2d 34 30 30 65 2d 61 63 37 37 2d 64 62 38 35 64 64 63 65 32 32 31 66 } //01 00  836c4ee0-849e-400e-ac77-db85ddce221f
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //00 00  DownloadData
	condition:
		any of ($a_*)
 
}