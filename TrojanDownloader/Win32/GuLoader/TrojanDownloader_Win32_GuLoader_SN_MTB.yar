
rule TrojanDownloader_Win32_GuLoader_SN_MTB{
	meta:
		description = "TrojanDownloader:Win32/GuLoader.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 "
		
	strings :
		$a_01_0 = {58 79 6c 6f 67 72 61 } //1 Xylogra
		$a_01_1 = {4e 6f 76 69 63 65 68 6f 6f } //1 Novicehoo
		$a_01_2 = {4f 75 74 72 61 6e 67 } //1 Outrang
		$a_01_3 = {42 6f 63 65 6d 65 6e 6e 65 } //1 Bocemenne
		$a_01_4 = {57 49 45 4e 45 52 4e 45 53 } //1 WIENERNES
		$a_01_5 = {4b 76 69 64 69 73 } //1 Kvidis
		$a_01_6 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //20 MSVBVM60.DLL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*20) >=25
 
}
rule TrojanDownloader_Win32_GuLoader_SN_MTB_2{
	meta:
		description = "TrojanDownloader:Win32/GuLoader.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 0b 00 00 "
		
	strings :
		$a_01_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //10 MSVBVM60.DLL
		$a_01_1 = {46 6f 72 64 61 6e 73 6b 65 74 } //1 Fordansket
		$a_01_2 = {53 70 6f 72 61 6e 67 69 6f 6c 75 6d } //1 Sporangiolum
		$a_01_3 = {53 50 4f 52 4f 43 48 4e 55 53 } //1 SPOROCHNUS
		$a_01_4 = {53 54 4f 52 59 57 4f 52 4b } //1 STORYWORK
		$a_01_5 = {4f 55 54 52 49 44 45 52 53 } //1 OUTRIDERS
		$a_01_6 = {6a 6f 69 6e 74 75 72 69 6e 67 } //1 jointuring
		$a_01_7 = {75 64 73 75 67 65 6e 64 65 } //1 udsugende
		$a_01_8 = {55 6e 73 69 73 74 69 6e 67 } //1 Unsisting
		$a_01_9 = {53 41 4e 54 49 4e 4f 4d 45 4c 4d 4f 5a 44 } //1 SANTINOMELMOZD
		$a_01_10 = {4d 69 75 73 79 4c 61 54 72 6f 69 6f } //1 MiusyLaTroio
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=17
 
}