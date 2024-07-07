
rule TrojanDownloader_O97M_Obfuse_AD_MSR{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.AD!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //1 Sub Auto_Open()
		$a_03_1 = {44 69 6d 20 90 02 09 20 41 73 20 53 74 72 69 6e 67 90 00 } //1
		$a_00_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 22 22 49 45 58 20 28 28 6e 65 77 2d 6f 62 6a 65 63 74 20 6e 65 74 2e 77 65 62 63 6c 69 65 6e 74 29 } //1 powershell.exe ""IEX ((new-object net.webclient)
		$a_00_3 = {2e 64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f } //1 .downloadstring('https://pastebin.com/raw/
		$a_03_4 = {53 68 65 6c 6c 20 28 90 02 06 29 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Obfuse_AD_MSR_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.AD!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 90 02 15 22 29 2e 43 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 90 02 15 22 29 90 00 } //1
		$a_02_1 = {4b 69 6c 6c 20 28 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 90 02 10 2e 65 78 65 90 00 } //1
		$a_00_2 = {3d 20 50 72 6f 63 65 73 73 2e 43 72 65 61 74 65 28 43 69 70 68 65 72 28 46 72 6f 6d 42 61 73 65 36 34 28 } //1 = Process.Create(Cipher(FromBase64(
		$a_02_3 = {50 72 6f 63 65 73 73 2e 43 72 65 61 74 65 28 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 90 02 10 2e 65 78 65 22 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}