
rule TrojanDownloader_Win32_Banload_BGF{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 73 23 b8 ?? ?? ?? 00 ba ?? ?? ?? 00 e8 ?? ?? (fb|fc) ff b8 ?? ?? ?? 00 ba ?? ?? ?? 00 e8 ?? ?? (fb|fc) ff e8 ?? ?? ff ff 33 c0 } //1
		$a_03_1 = {0f b7 44 70 fe e8 ?? ?? ff ff 5a 32 d0 88 55 ?? 8d 45 ?? e8 ?? ?? ?? ff 0f b6 55 ?? 66 89 54 70 fe 46 4f 0f 85 4a ff ff ff } //1
		$a_01_2 = {25 01 00 00 80 79 05 48 83 c8 fe 40 99 52 50 8d 45 d0 e8 c0 fe ff ff 8b 45 d0 8d 55 ec e8 29 fd ff ff d1 fb 79 03 83 d3 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}