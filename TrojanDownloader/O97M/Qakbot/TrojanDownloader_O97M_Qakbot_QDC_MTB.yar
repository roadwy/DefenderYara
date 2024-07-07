
rule TrojanDownloader_O97M_Qakbot_QDC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.QDC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {5c 49 45 55 44 4c 4b 2e 43 4a 46 90 02 04 67 69 66 90 00 } //1
		$a_01_1 = {72 75 6e 64 6c 6c 33 } //1 rundll3
		$a_01_2 = {44 6c 6c 52 } //1 DllR
		$a_01_3 = {4c 4d 6f 6e } //1 LMon
		$a_01_4 = {65 72 53 65 72 76 65 72 } //1 erServer
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}