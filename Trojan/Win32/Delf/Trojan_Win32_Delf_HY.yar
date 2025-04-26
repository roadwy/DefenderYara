
rule Trojan_Win32_Delf_HY{
	meta:
		description = "Trojan:Win32/Delf.HY,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5b 48 4b 45 59 5f 43 4c 41 53 53 45 53 5f 52 4f 4f 54 5c 43 4c 53 49 44 5c 7b 5b 46 6f 6c 64 65 72 49 44 5d 7d 5c 53 68 65 6c 6c 5c 4f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 5d } //1 [HKEY_CLASSES_ROOT\CLSID\{[FolderID]}\Shell\Open\Command]
		$a_01_1 = {42 75 74 74 6f 6e 43 72 65 61 74 51 75 69 63 6b 4c 61 75 6e 63 68 43 6c 69 63 6b } //1 ButtonCreatQuickLaunchClick
		$a_01_2 = {7b 31 66 34 64 65 33 37 30 2d 64 36 32 37 2d 31 31 64 31 2d 62 61 34 66 2d 30 30 61 30 63 39 31 65 65 64 62 61 7d } //1 {1f4de370-d627-11d1-ba4f-00a0c91eedba}
		$a_01_3 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 2e 6c 6e 6b } //1 \Internet Explorer.lnk
		$a_01_4 = {3a 3a 7b 32 30 44 30 34 46 45 30 2d 33 41 45 41 2d 31 30 36 39 2d 41 32 44 38 2d 30 38 30 30 32 42 33 30 33 30 39 44 7d } //1 ::{20D04FE0-3AEA-1069-A2D8-08002B30309D}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}