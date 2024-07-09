
rule TrojanDownloader_O97M_IcedId_BK_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedId.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 70 6c 69 74 28 61 71 4d 58 5a 39 28 66 72 6d 2e 70 61 74 68 73 2e 74 65 78 74 29 2c 20 22 7c 22 29 } //1 = Split(aqMXZ9(frm.paths.text), "|")
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 28 61 4a 4e 79 43 29 } //1 = CreateObject("wscript.shell").exec(aJNyC)
		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 61 76 56 66 65 62 22 2c 20 61 31 34 62 76 63 20 26 20 22 20 22 20 26 20 61 78 59 6a 47 20 26 20 22 6d 61 74 20 3a 20 22 22 22 20 26 20 61 55 7a 33 43 63 20 26 } //1 Application.Run "avVfeb", a14bvc & " " & axYjG & "mat : """ & aUz3Cc &
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_IcedId_BK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/IcedId.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c 22 20 26 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 56 65 72 73 69 6f 6e 20 26 20 22 5c 57 6f 72 64 5c 53 65 63 75 72 69 74 79 5c 41 63 63 65 73 73 56 42 4f 4d 22 } //1 = "HKEY_CURRENT_USER\Software\Microsoft\Office\" & Application.Version & "\Word\Security\AccessVBOM"
		$a_03_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 52 65 67 57 72 69 74 65 20 [0-1e] 2c 20 31 2c 20 22 52 45 47 5f 44 57 4f 52 44 22 } //1
		$a_03_2 = {3d 20 4d 69 64 28 [0-1e] 2c 20 34 20 2f 20 32 2c 20 33 30 30 30 30 30 30 29 } //1
		$a_01_3 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 22 2c 20 22 77 6f 72 64 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 = GetObject("", "word.application")
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}