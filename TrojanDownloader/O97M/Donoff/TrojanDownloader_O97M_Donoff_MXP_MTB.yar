
rule TrojanDownloader_O97M_Donoff_MXP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.MXP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 79 55 52 4c 20 3d 20 22 68 74 74 70 73 3a 2f 2f 6c 6f 6e 67 2e 61 66 2f 46 61 63 74 44 6f 77 6e 50 61 72 74 79 22 } //1 myURL = "https://long.af/FactDownParty"
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 4d 4c 32 2e 53 65 72 76 65 72 58 4d 4c 48 54 54 50 2e 36 2e 30 22 29 } //1 CreateObject("MSXML2.ServerXMLHTTP.6.0")
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 44 4f 44 42 2e 53 74 72 65 61 6d 22 29 } //1 CreateObject("ADODB.Stream")
		$a_01_3 = {53 61 76 65 54 6f 46 69 6c 65 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 } //1 SaveToFile Environ("USERPROFILE")
		$a_01_4 = {57 72 69 74 65 20 57 69 6e 48 74 74 70 52 65 71 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 } //1 Write WinHttpReq.responseBody
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}