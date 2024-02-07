
rule TrojanDownloader_Win32_Banload_ZEE{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZEE,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {55 61 63 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 00 } //0a 00 
		$a_01_1 = {61 6f 20 61 62 72 69 72 20 6f 20 61 72 71 75 69 76 6f } //0a 00  ao abrir o arquivo
		$a_01_2 = {63 65 72 74 69 66 69 63 6f 2e 63 6f 6d 2e 62 72 2f } //01 00  certifico.com.br/
		$a_01_3 = {54 6d 61 69 6e 30 31 39 32 39 30 } //00 00  Tmain019290
		$a_00_4 = {78 9f 00 00 04 00 04 00 05 00 00 } //01 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Banload_ZEE_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZEE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 61 63 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 00 } //01 00 
		$a_01_1 = {61 6f 20 61 62 72 69 72 20 6f 20 61 72 71 75 69 76 6f } //01 00  ao abrir o arquivo
		$a_01_2 = {54 41 70 70 4a 61 76 61 } //01 00  TAppJava
		$a_01_3 = {54 47 65 72 6d 69 6e 67 } //01 00  TGerming
		$a_03_4 = {8d 45 f8 e8 85 fe ff ff ff 75 f8 68 90 01 04 68 90 01 04 68 90 01 04 68 90 01 04 68 90 01 04 68 90 01 04 68 90 01 04 68 90 01 04 90 02 10 8d 45 fc ba 90 01 01 00 00 00 e8 90 01 04 8b 4d fc ba 90 01 04 8b c3 e8 90 01 04 33 c0 90 00 } //00 00 
		$a_00_5 = {78 b2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Banload_ZEE_3{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZEE,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {55 61 63 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 00 } //0a 00 
		$a_01_1 = {61 6f 20 61 62 72 69 72 20 6f 20 61 72 71 75 69 76 6f } //0a 00  ao abrir o arquivo
		$a_01_2 = {2e 6d 65 64 69 61 74 6f 77 6e 2e 63 6f 6d 2e 62 72 } //0a 00  .mediatown.com.br
		$a_01_3 = {2e 63 6f 70 65 72 63 61 6e 61 2e 63 6f 6d 2e 62 72 } //01 00  .copercana.com.br
		$a_01_4 = {4f 00 57 00 53 00 5c 00 63 00 74 00 66 00 6d 00 6f 00 6e 00 } //01 00  OWS\ctfmon
		$a_01_5 = {4f 00 57 00 53 00 5c 00 74 00 61 00 73 00 6b 00 6d 00 61 00 6e 00 } //01 00  OWS\taskman
		$a_01_6 = {74 61 73 6b 6d 61 6e 6e 2e 65 78 65 } //01 00  taskmann.exe
		$a_03_7 = {6d 6f 6d 33 00 90 01 0b 32 2e 90 00 } //00 00 
		$a_00_8 = {80 10 00 00 c5 b9 33 c6 2f 80 1a } //4c 1a 
	condition:
		any of ($a_*)
 
}