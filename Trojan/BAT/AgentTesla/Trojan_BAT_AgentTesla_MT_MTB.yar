
rule Trojan_BAT_AgentTesla_MT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,53 00 53 00 13 00 00 "
		
	strings :
		$a_01_0 = {6b 4c 6a 77 34 69 49 73 43 4c 73 5a 74 78 63 34 6c 6b 73 4e 30 6a } //20 kLjw4iIsCLsZtxc4lksN0j
		$a_01_1 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //10 DebuggableAttribute
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //10 DownloadFile
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //10 CreateInstance
		$a_01_4 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //10 MemoryStream
		$a_01_5 = {52 65 76 65 72 73 65 } //10 Reverse
		$a_01_6 = {52 65 70 6c 61 63 65 } //10 Replace
		$a_01_7 = {58 62 51 31 34 61 44 54 33 43 76 68 31 65 70 4b 35 39 63 } //1 XbQ14aDT3Cvh1epK59c
		$a_01_8 = {51 42 50 79 37 6f 44 76 42 6b 58 43 71 6f 68 45 71 32 4c } //1 QBPy7oDvBkXCqohEq2L
		$a_01_9 = {62 57 39 53 31 34 44 79 37 47 59 39 69 6f 36 6d 76 4c 56 } //1 bW9S14Dy7GY9io6mvLV
		$a_01_10 = {49 68 75 53 71 6c 6c 50 74 55 6f 76 39 53 79 6d 75 76 69 } //1 IhuSqllPtUov9Symuvi
		$a_01_11 = {4f 6a 5a 4e 45 58 6c 43 47 4b 35 4c 55 77 76 38 52 72 66 } //1 OjZNEXlCGK5LUwv8Rrf
		$a_01_12 = {69 68 61 54 45 51 6c 72 33 52 59 35 51 63 55 52 52 37 31 } //1 ihaTEQlr3RY5QcURR71
		$a_01_13 = {67 34 74 6f 46 4e 6f 67 75 67 56 46 74 66 70 34 78 4c 35 } //1 g4toFNogugVFtfp4xL5
		$a_01_14 = {45 36 4b 4b 69 4c 6f 44 38 77 45 79 59 67 5a 49 79 50 70 } //1 E6KKiLoD8wEyYgZIyPp
		$a_01_15 = {62 70 53 46 48 55 6f 6a 6a 67 37 77 4b 44 63 6f 6f 57 48 } //1 bpSFHUojjg7wKDcooWH
		$a_01_16 = {57 4e 39 70 5a 6a 42 46 46 54 6a 67 46 6e 54 72 38 36 47 } //1 WN9pZjBFFTjgFnTr86G
		$a_01_17 = {4f 6e 67 66 4c 57 42 45 33 4f 6d 46 59 36 68 76 69 68 45 } //1 OngfLWBE3OmFY6hvihE
		$a_01_18 = {68 65 56 71 78 4f 42 51 4d 77 46 34 54 49 67 6c 45 56 54 } //1 heVqxOBQMwF4TIglEVT
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1) >=83
 
}