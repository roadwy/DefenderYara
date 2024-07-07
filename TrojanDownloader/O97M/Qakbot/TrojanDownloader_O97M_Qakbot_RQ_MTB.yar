
rule TrojanDownloader_O97M_Qakbot_RQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.RQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 2e 2e 5c 4c 69 66 61 73 2e 76 65 72 32 22 } //1 = "..\Lifas.ver2"
		$a_01_1 = {53 75 62 20 61 75 74 6f 5f 6f 70 65 6e 28 29 } //1 Sub auto_open()
		$a_01_2 = {53 65 74 20 46 65 72 61 20 3d 20 45 78 63 65 6c 34 49 6e 74 6c 4d 61 63 72 6f 53 68 65 65 74 73 } //1 Set Fera = Excel4IntlMacroSheets
		$a_01_3 = {6e 65 74 20 3d 20 22 75 52 22 0d 0a 6e 65 74 31 20 3d 20 22 4d 6f 6e 22 0d 0a 64 66 66 20 3d 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 22 0d 0a 64 66 66 31 20 3d 20 22 54 6f 46 69 6c 65 41 22 } //1
		$a_01_4 = {22 3d 48 41 4c 54 28 29 22 } //1 "=HALT()"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}