
rule TrojanDownloader_PowerShell_Elshutilo_CS_eml{
	meta:
		description = "TrojanDownloader:PowerShell/Elshutilo.CS!eml,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 20 52 65 70 6c 61 63 65 28 [0-0b] 2c 20 22 [0-2a] 22 2c 20 22 22 29 } //1
		$a_01_1 = {53 65 74 20 65 72 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 Set er = CreateObject("WScript.Shell")
		$a_01_2 = {65 72 2e 52 75 6e } //1 er.Run
		$a_03_3 = {6c 69 6e 65 54 65 78 74 90 0a 1e 00 3d 20 [0-0f] 20 2b 20 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}