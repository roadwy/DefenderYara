
rule TrojanDownloader_Win32_Banload_ZEE{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZEE,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 61 63 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 00 } //10
		$a_01_1 = {61 6f 20 61 62 72 69 72 20 6f 20 61 72 71 75 69 76 6f } //10 ao abrir o arquivo
		$a_01_2 = {63 65 72 74 69 66 69 63 6f 2e 63 6f 6d 2e 62 72 2f } //10 certifico.com.br/
		$a_01_3 = {54 6d 61 69 6e 30 31 39 32 39 30 } //1 Tmain019290
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1) >=31
 
}
rule TrojanDownloader_Win32_Banload_ZEE_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZEE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 61 63 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 00 } //1
		$a_01_1 = {61 6f 20 61 62 72 69 72 20 6f 20 61 72 71 75 69 76 6f } //1 ao abrir o arquivo
		$a_01_2 = {54 41 70 70 4a 61 76 61 } //1 TAppJava
		$a_01_3 = {54 47 65 72 6d 69 6e 67 } //1 TGerming
		$a_03_4 = {8d 45 f8 e8 85 fe ff ff ff 75 f8 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? [0-10] 8d 45 fc ba ?? 00 00 00 e8 ?? ?? ?? ?? 8b 4d fc ba ?? ?? ?? ?? 8b c3 e8 ?? ?? ?? ?? 33 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}
rule TrojanDownloader_Win32_Banload_ZEE_3{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZEE,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 08 00 00 "
		
	strings :
		$a_01_0 = {55 61 63 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 00 } //10
		$a_01_1 = {61 6f 20 61 62 72 69 72 20 6f 20 61 72 71 75 69 76 6f } //10 ao abrir o arquivo
		$a_01_2 = {2e 6d 65 64 69 61 74 6f 77 6e 2e 63 6f 6d 2e 62 72 } //10 .mediatown.com.br
		$a_01_3 = {2e 63 6f 70 65 72 63 61 6e 61 2e 63 6f 6d 2e 62 72 } //10 .copercana.com.br
		$a_01_4 = {4f 00 57 00 53 00 5c 00 63 00 74 00 66 00 6d 00 6f 00 6e 00 } //1 OWS\ctfmon
		$a_01_5 = {4f 00 57 00 53 00 5c 00 74 00 61 00 73 00 6b 00 6d 00 61 00 6e 00 } //1 OWS\taskman
		$a_01_6 = {74 61 73 6b 6d 61 6e 6e 2e 65 78 65 } //1 taskmann.exe
		$a_03_7 = {6d 6f 6d 33 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32 2e } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*1) >=31
 
}