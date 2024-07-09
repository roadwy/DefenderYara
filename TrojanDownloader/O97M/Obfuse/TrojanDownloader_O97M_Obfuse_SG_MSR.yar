
rule TrojanDownloader_O97M_Obfuse_SG_MSR{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SG!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {58 45 31 70 59 33 4a 76 63 32 39 6d 64 46 78 58 61 57 35 6b 62 33 64 7a 58 46 4e 30 59 58 4a 30 49 45 31 6c 62 6e 56 63 55 48 4a 76 5a 33 4a 68 62 58 4e 63 55 33 52 68 63 6e 52 31 63 46 78 68 5a 32 56 75 64 43 35 6c 65 47 55 3d } //1 XE1pY3Jvc29mdFxXaW5kb3dzXFN0YXJ0IE1lbnVcUHJvZ3JhbXNcU3RhcnR1cFxhZ2VudC5leGU=
		$a_03_1 = {22 61 48 52 30 63 44 6f 76 4c 7a [0-3e] 79 64 57 35 6b 62 47 77 7a 4d 69 35 6c 65 47 55 3d 22 } //1
		$a_01_2 = {43 53 74 72 28 45 6e 76 69 72 6f 6e 28 22 41 70 70 44 61 74 61 22 29 } //1 CStr(Environ("AppData")
		$a_01_3 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_01_4 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29 } //1 CreateObject("Microsoft.XMLHTTP")
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}