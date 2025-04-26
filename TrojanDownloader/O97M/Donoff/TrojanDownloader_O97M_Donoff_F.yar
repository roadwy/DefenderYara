
rule TrojanDownloader_O97M_Donoff_F{
	meta:
		description = "TrojanDownloader:O97M/Donoff.F,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-10] 20 2b 20 [0-10] 20 2b 20 [0-10] 20 2b 20 22 72 69 70 22 20 2b 20 4c 43 61 73 65 28 65 72 72 6f 72 4d 73 67 29 20 2b 20 22 2e 53 68 22 20 2b 20 61 72 67 75 6d 65 6e 74 73 20 2b 20 22 6c 6c } //1
		$a_01_1 = {2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 55 43 61 73 65 28 22 70 22 29 20 2b 20 22 72 6f 63 22 20 2b 20 61 72 67 75 6d 65 6e 74 73 20 2b 20 22 73 73 } //1 .Environment(UCase("p") + "roc" + arguments + "ss
		$a_01_2 = {2e 77 72 69 74 65 20 43 6f 64 4f 72 64 69 6e 65 43 6f 72 72 65 6e 74 65 31 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 } //1 .write CodOrdineCorrente1.responseBody
		$a_01_3 = {55 74 69 6c 73 49 6e 64 32 53 75 62 2e 73 61 76 65 74 6f 66 69 6c 65 20 64 69 6d 49 6e 64 65 78 41 72 67 73 2c 20 32 } //1 UtilsInd2Sub.savetofile dimIndexArgs, 2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_F_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.F,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29 3a 20 56 61 72 5f 30 30 37 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f } //1 = CreateObject("Microsoft.XMLHTTP"): Var_007.Open "GET", "http://
		$a_01_1 = {2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 41 50 50 44 41 54 41 25 22 29 3a 20 44 69 6d 20 56 61 72 } //1 .ExpandEnvironmentStrings("%APPDATA%"): Dim Var
		$a_01_2 = {2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 3a 20 2e 73 61 76 65 74 6f 66 69 6c 65 20 56 61 72 5f 30 30 32 20 26 20 22 5c 73 65 72 76 69 63 65 5c 73 65 72 76 69 63 65 2e 65 78 65 22 2c } //1 .responseBody: .savetofile Var_002 & "\service\service.exe",
		$a_01_3 = {2e 52 75 6e 20 43 68 72 28 33 34 29 20 26 20 56 61 72 5f 30 31 34 20 26 20 43 68 72 28 33 34 29 2c 20 31 2c 20 54 72 75 65 3a } //1 .Run Chr(34) & Var_014 & Chr(34), 1, True:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}