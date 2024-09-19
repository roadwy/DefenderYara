
rule Ransom_Win32_FileCoder_PC_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 89 f9 81 c1 35 1b 00 00 66 89 cb 8b 4c 24 ?? 66 89 5c 24 ?? 8a 84 01 ?? ?? ?? ?? 88 44 24 ?? 8b 4c 24 ?? 8b 54 24 ?? 0f b6 0c 0a 66 89 7c 24 ?? 0f b6 54 24 ?? 29 d1 88 c8 88 44 24 ?? 8b 4c 24 ?? 8b 54 24 ?? 09 c9 09 d2 8b 74 24 ?? 89 54 24 ?? 89 4c 24 ?? 8b 4c 24 ?? 88 04 31 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Ransom_Win32_FileCoder_PC_MTB_2{
	meta:
		description = "Ransom:Win32/FileCoder.PC!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 2f 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 6c 00 65 00 72 00 } //1 Ransomware/RansomwareController
		$a_01_1 = {59 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 77 00 65 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 2e 00 } //1 Your files were encrypted.
		$a_01_2 = {53 50 49 5f 53 45 54 44 45 53 4b 57 41 4c 4c 50 41 50 45 52 } //1 SPI_SETDESKWALLPAPER
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 52 65 6d 6f 74 65 49 6d 61 67 65 46 69 6c 65 } //1 DownloadRemoteImageFile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}