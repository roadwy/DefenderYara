
rule TrojanDownloader_Win32_Squiblydoo_AN_MTB{
	meta:
		description = "TrojanDownloader:Win32/Squiblydoo.AN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {57 53 63 72 69 70 74 2e 53 68 65 6c 6c } //1 WScript.Shell
		$a_00_1 = {57 69 4e 6d 47 6d 54 73 3a 7b 49 6d 50 65 52 73 4f 6e 41 74 49 6f 4e 6c 45 76 45 6c 3d 49 6d 50 65 52 73 4f 6e } //1 WiNmGmTs:{ImPeRsOnAtIoNlEvEl=ImPeRsOn
		$a_02_2 = {72 65 67 73 76 72 33 32 20 2f 75 20 2f 6e 20 2f 73 20 2f 69 3a (68 74 74 70|68 74 74 70 73) 3a 2f 2f [0-25] 20 73 63 72 6f 62 6a 2e 64 6c 6c } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*2) >=3
 
}