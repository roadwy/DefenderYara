
rule TrojanDownloader_O97M_Obfuse_PS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {49 2d 57 6f 72 6d 2e 4b 61 6d 69 6c 61 } //1 I-Worm.Kamila
		$a_00_1 = {4b 69 6c 6c 20 22 43 3a 5c 6b 61 6d 61 2e 64 6c 6c } //1 Kill "C:\kama.dll
		$a_00_2 = {77 73 68 2e 52 75 6e 20 22 43 3a 5c 6b 61 6d 5f 64 72 6f 70 2e 76 62 73 } //1 wsh.Run "C:\kam_drop.vbs
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Obfuse_PS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {75 52 6c 4d 6f 6e } //1 uRlMon
		$a_00_1 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //1 CreateDirectoryA
		$a_00_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_00_3 = {43 3a 5c 48 75 79 74 5c 52 69 6b 6f 6c 5c 47 65 72 74 69 6b } //1 C:\Huyt\Rikol\Gertik
		$a_00_4 = {55 52 4c 44 6f 77 6e 6c } //1 URLDownl
		$a_00_5 = {6f 61 64 54 6f 46 69 6c 65 41 2d } //1 oadToFileA-
		$a_00_6 = {68 74 74 70 3a 2f 2f 63 61 6d 69 6c 6c 61 64 65 72 72 69 63 6f 2e 63 6f 6d 2f 66 6f 6e 74 73 2f 72 65 6c 64 65 76 6f 70 73 2e 64 6c 6c } //1 http://camilladerrico.com/fonts/reldevops.dll
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}