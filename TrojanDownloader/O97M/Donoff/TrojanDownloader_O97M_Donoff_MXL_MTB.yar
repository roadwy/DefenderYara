
rule TrojanDownloader_O97M_Donoff_MXL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.MXL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0c 00 0c 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //02 00  ShellExecuteA
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 4d 4c 32 2e 53 65 72 76 65 72 58 4d 4c 48 54 54 50 22 29 } //02 00  CreateObject("MSXML2.ServerXMLHTTP")
		$a_01_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 20 34 32 34 32 33 34 32 2c 20 22 6f 70 65 6e 22 } //02 00  ShellExecute 4242342, "open"
		$a_01_3 = {49 73 55 73 65 72 41 6e 41 64 6d 69 6e 20 4c 69 62 20 22 73 68 65 6c 6c 33 32 22 } //02 00  IsUserAnAdmin Lib "shell32"
		$a_01_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 20 34 35 34 33 34 35 2c 20 22 6f 70 65 6e 22 } //02 00  ShellExecute 454345, "open"
		$a_01_5 = {55 55 49 44 28 22 68 74 74 70 73 3a 2f 2f 75 73 61 6d 79 66 6f 72 65 76 65 72 2e 61 7a 75 72 65 65 64 67 65 2e 6e 65 74 2f 66 6d 6e 66 69 65 69 6b 66 65 6d 73 64 66 64 73 73 64 66 2f 66 6a 61 66 69 73 69 73 61 66 65 67 35 34 2f 65 78 63 65 6c 2e 74 78 74 } //00 00  UUID("https://usamyforever.azureedge.net/fmnfieikfemsdfdssdf/fjafisisafeg54/excel.txt
	condition:
		any of ($a_*)
 
}