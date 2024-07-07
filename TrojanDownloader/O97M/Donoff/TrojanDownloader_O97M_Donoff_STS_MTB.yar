
rule TrojanDownloader_O97M_Donoff_STS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.STS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 46 69 6c 65 20 3d 20 22 68 74 74 70 3a 2f 2f 61 30 37 35 31 30 30 37 2e 78 73 70 68 2e 72 75 2f 75 72 45 68 4c 39 35 72 2e 65 78 65 22 } //1 URLFile = "http://a0751007.xsph.ru/urEhL95r.exe"
		$a_01_1 = {4d 73 67 42 6f 78 20 22 54 68 65 20 64 6f 63 75 6d 65 6e 74 20 69 73 20 70 72 6f 74 65 63 74 65 64 22 2c 20 76 62 49 6e 66 6f 72 6d 61 74 69 6f 6e 2c 20 22 54 68 65 20 64 6f 63 75 6d 65 6e 74 20 69 73 20 70 72 6f 74 65 63 74 65 64 22 } //1 MsgBox "The document is protected", vbInformation, "The document is protected"
		$a_01_2 = {4d 73 67 42 6f 78 20 22 3f 3f 3f 3f 3f 3f 20 3f 20 22 20 26 20 53 74 61 74 75 73 2c 20 76 62 45 78 63 6c 61 6d 61 74 69 6f 6e 2c 20 22 3f 3f 3f 3f 3f 3f 22 } //1 MsgBox "?????? ? " & Status, vbExclamation, "??????"
		$a_01_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 52 75 6e 20 22 22 22 22 20 26 20 4b 61 74 61 6c 6f 67 20 26 20 22 5c 22 20 26 20 4e 61 6d 65 46 69 6c 65 49 6e 20 26 20 22 22 22 22 } //1 CreateObject("wscript.shell").Run """" & Katalog & "\" & NameFileIn & """"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}