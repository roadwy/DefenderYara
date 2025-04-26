
rule Trojan_Win32_Guloader_ASJ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {74 68 65 72 6d 65 6c 73 5c 64 65 6b 61 74 65 72 65 6e 64 65 73 2e 69 6e 69 } //1 thermels\dekaterendes.ini
		$a_01_1 = {74 69 6b 72 6f 6e 65 73 65 64 6c 65 72 5c 70 68 79 74 6f 67 65 6f 67 72 61 70 68 69 63 61 6c } //1 tikronesedler\phytogeographical
		$a_01_2 = {4e 6f 6e 73 75 62 73 69 73 74 65 6e 74 2e 74 78 74 } //1 Nonsubsistent.txt
		$a_01_3 = {65 6c 65 6b 74 72 6f 6e 69 6b 66 69 72 6d 61 65 72 5c 56 65 73 74 69 62 75 6c 65 72 73 2e 67 65 72 } //1 elektronikfirmaer\Vestibulers.ger
		$a_01_4 = {61 70 68 72 6f 64 65 73 69 61 63 5c 55 6e 69 6e 73 74 61 6c 6c 5c 63 61 72 74 65 5c 66 69 6e 61 6e 63 69 65 72 65 64 } //1 aphrodesiac\Uninstall\carte\financiered
		$a_01_5 = {66 65 61 74 68 65 72 69 65 73 74 5c 53 68 61 64 6f 6f 66 37 36 2e 53 6b 79 31 34 33 } //1 featheriest\Shadoof76.Sky143
		$a_01_6 = {71 75 65 72 69 6d 6f 6e 69 6f 75 73 6c 79 5c 4e 65 6d 61 74 6f 67 6e 61 74 68 6f 75 73 2e 64 6c 6c } //1 querimoniously\Nematognathous.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}