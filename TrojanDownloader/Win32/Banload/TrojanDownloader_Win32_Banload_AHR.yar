
rule TrojanDownloader_Win32_Banload_AHR{
	meta:
		description = "TrojanDownloader:Win32/Banload.AHR,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 73 4c 71 38 35 54 70 51 35 44 65 50 4d 6e 69 38 33 71 57 4c 72 44 5a 53 63 62 6d 54 32 76 33 53 63 4c 58 54 } //02 00  SsLq85TpQ5DePMni83qWLrDZScbmT2v3ScLXT
		$a_01_1 = {30 59 4e 33 6d 79 52 63 7a 6a 50 4a 75 2b 42 63 6e 6b 51 6f 38 66 47 36 7a 4a 51 36 4c 69 52 } //02 00  0YN3myRczjPJu+BcnkQo8fG6zJQ6LiR
		$a_01_2 = {48 66 53 63 4c 5a 54 36 7a 6f 55 49 30 7a 38 37 44 71 53 61 62 6b 51 4d 44 66 4f 4e 39 30 52 72 44 65 50 4d 6e 69 4a 36 62 6b 51 6f 76 4a 4f 4e 50 62 } //02 00  HfScLZT6zoUI0z87DqSabkQMDfON90RrDePMniJ6bkQovJONPb
		$a_01_3 = {42 63 44 6f 50 4d 35 71 50 47 } //01 00  BcDoPM5qPG
		$a_01_4 = {46 33 6e 6b 52 73 72 62 46 5a 75 } //01 00  F3nkRsrbFZu
		$a_01_5 = {46 33 6e 5a 4f 4d 72 66 52 63 58 6c 46 5a 75 } //00 00  F3nZOMrfRcXlFZu
	condition:
		any of ($a_*)
 
}