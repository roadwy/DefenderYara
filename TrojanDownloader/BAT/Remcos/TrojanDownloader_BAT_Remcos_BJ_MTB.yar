
rule TrojanDownloader_BAT_Remcos_BJ_MTB{
	meta:
		description = "TrojanDownloader:BAT/Remcos.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 2b 7e ?? ?? ?? 04 07 7e ?? ?? ?? 04 07 91 7e ?? ?? ?? 04 07 7e ?? ?? ?? 04 8e 69 5d 91 06 58 20 ?? ?? ?? ?? 5f 61 d2 9c 07 17 58 0b 07 7e ?? ?? ?? 04 8e 69 17 59 fe 02 16 fe 01 0c 08 2d } //2
		$a_01_1 = {72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //1 rdapp.com
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}