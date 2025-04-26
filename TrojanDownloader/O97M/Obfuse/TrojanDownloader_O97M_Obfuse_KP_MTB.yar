
rule TrojanDownloader_O97M_Obfuse_KP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //1 Sub Auto_Open()
		$a_00_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 22 22 49 45 58 20 28 28 6e 65 77 2d 6f 62 6a 65 63 74 20 6e 65 74 2e 77 65 62 63 6c 69 65 6e 74 29 } //1 powershell.exe ""IEX ((new-object net.webclient)
		$a_00_2 = {2e 64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f } //1 .downloadstring('https://pastebin.com/raw/
		$a_00_3 = {47 65 74 2d 43 6f 6d 70 75 74 65 72 44 65 74 61 69 6c 73 } //1 Get-ComputerDetails
		$a_03_4 = {53 68 65 6c 6c 20 28 [0-09] 29 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}