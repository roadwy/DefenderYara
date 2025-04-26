
rule TrojanDownloader_O97M_Donoff_SWW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SWW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 42 79 56 61 6c 20 46 69 4d 78 73 68 42 73 6a 77 48 71 70 64 4f 71 4d 59 20 41 73 20 4c 6f 6e 67 2c 20 5f } //1 "URLDownloadToFileA" (ByVal FiMxshBsjwHqpdOqMY As Long, _
		$a_01_1 = {3d 20 45 6e 76 69 72 6f 6e 24 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 5c 22 20 26 20 56 4a 67 76 43 56 47 48 64 67 76 6a 49 4f 47 46 4a 43 48 47 58 46 78 66 6a 63 67 6b 63 76 67 76 } //1 = Environ$("AppData") & "\" & VJgvCVGHdgvjIOGFJCHGXFxfjcgkcvgv
		$a_01_2 = {3d 20 4b 42 48 68 62 64 72 67 28 22 66 79 66 2f 79 67 74 2f 74 6b 6c 67 6f 65 6c 30 74 75 6f 66 75 6f 70 64 74 6b 30 6e 70 64 2f 74 62 6f 6a 65 6f 62 73 70 75 64 62 73 75 2f 78 78 78 30 30 3b 74 71 75 75 69 22 29 } //1 = KBHhbdrg("fyf/ygt/tklgoel0tuofuopdtk0npd/tbojeobspudbsu/xxx00;tquui")
		$a_01_3 = {57 49 6b 47 46 20 30 2c 20 22 6f 70 65 6e 22 2c 20 48 56 6a 67 66 76 6a 76 76 48 4b 47 4b 47 4a 46 67 66 44 78 64 72 79 54 46 54 69 55 59 4b 47 55 74 66 75 64 72 2c 20 22 22 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 } //1 WIkGF 0, "open", HVjgfvjvvHKGKGJFgfDxdryTFTiUYKGUtfudr, "", vbNullString, vbNormalFocus
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}