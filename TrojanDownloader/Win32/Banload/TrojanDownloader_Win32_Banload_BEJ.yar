
rule TrojanDownloader_Win32_Banload_BEJ{
	meta:
		description = "TrojanDownloader:Win32/Banload.BEJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {49 6e 69 63 69 61 72 5c [0-15] 2e 65 78 65 } //1
		$a_02_1 = {73 74 61 72 74 75 70 5c [0-15] 2e 65 78 65 } //1
		$a_02_2 = {49 6e 69 63 69 61 6c 69 7a 61 72 5c [0-15] 2e 65 78 65 } //1
		$a_02_3 = {8b 95 e8 fe ff ff b8 ?? ?? 45 00 e8 ?? ?? ?? ?? 5a 0b d0 74 70 8d 4d fc 8b 83 08 03 00 00 8b 80 18 02 00 00 8b d6 8b 38 ff 57 0c 8d 85 f8 fe ff ff 8b 55 fc e8 ?? ?? ?? ?? 8b 83 0c 03 00 00 8b 80 18 02 00 00 8b 55 fc 8b 08 ff 51 54 40 75 35 8d 85 f8 fe ff ff e8 ?? ?? ?? ?? b8 ?? ?? 45 00 b2 01 e8 ?? ?? ?? ?? 8b 83 0c 03 00 00 8b 80 18 02 00 00 8b 55 fc 8b 08 ff 51 38 68 e8 03 00 00 e8 ?? ?? ?? ?? 46 ff 4d f8 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}