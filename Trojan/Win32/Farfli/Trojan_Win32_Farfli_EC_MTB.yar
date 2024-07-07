
rule Trojan_Win32_Farfli_EC_MTB{
	meta:
		description = "Trojan:Win32/Farfli.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {40 73 68 69 66 74 20 2f 30 } //1 @shift /0
		$a_81_1 = {26 40 63 6c 73 26 40 73 65 74 } //1 &@cls&@set
		$a_81_2 = {3d 31 70 4c 64 73 57 47 6a 33 63 34 72 71 4a 32 4b 74 37 36 61 69 68 54 5a 52 6c 6f 55 59 42 4d 62 6d 77 6b } //1 =1pLdsWGj3c4rqJ2Kt76aihTZRloUYBMbmwk
		$a_81_3 = {51 48 49 39 30 53 50 76 65 43 38 35 7a 41 66 67 79 45 4f 44 75 46 4e 40 56 6e 78 58 } //1 QHI90SPveC85zAfgyEODuFN@VnxX
		$a_01_4 = {69 6e 69 63 69 6f } //1 inicio
		$a_01_5 = {64 65 73 63 70 75 } //1 descpu
		$a_01_6 = {6f 70 63 70 75 } //1 opcpu
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule Trojan_Win32_Farfli_EC_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {4d 65 6c 6f 64 79 2e 64 61 74 } //1 Melody.dat
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_2 = {45 6e 75 6d 50 72 6f 63 65 73 73 4d 6f 64 75 6c 65 73 } //1 EnumProcessModules
		$a_01_3 = {77 61 76 65 49 6e 53 74 61 72 74 } //1 waveInStart
		$a_01_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 41 } //1 ShellExecuteExA
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_01_6 = {44 65 66 57 69 6e 64 6f 77 50 72 6f 63 41 } //1 DefWindowProcA
		$a_01_7 = {43 6c 69 65 6e 74 20 68 6f 6f 6b } //1 Client hook
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}