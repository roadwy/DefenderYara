
rule TrojanDownloader_Win32_Banload_BCV{
	meta:
		description = "TrojanDownloader:Win32/Banload.BCV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 80 9c 00 00 00 30 75 00 00 8b 45 ec e8 ?? ?? ?? ?? 83 c0 54 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ec e8 ?? ?? ?? ?? 83 c0 70 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? b2 01 } //1
		$a_01_1 = {64 61 64 6f 73 3d 00 } //1
		$a_01_2 = {67 72 61 76 61 72 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}