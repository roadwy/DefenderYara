
rule TrojanDownloader_Win32_Banload_AFC{
	meta:
		description = "TrojanDownloader:Win32/Banload.AFC,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0f 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b f8 85 ff 74 69 8b d5 8d 44 24 04 e8 } //01 00 
		$a_01_1 = {64 75 61 72 74 65 2e 6d 61 63 68 61 64 6f 2e 73 69 74 65 73 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 } //01 00  duarte.machado.sites.uol.com.br
		$a_01_2 = {7e 64 6f 6e 77 6c 6f 61 64 2f 6d 6f 64 75 6c 6f 73 } //01 00  ~donwload/modulos
		$a_01_3 = {48 65 6c 70 65 72 2e 64 6c 6c 00 } //01 00 
		$a_01_4 = {73 76 68 6f 73 74 78 79 2e 65 78 65 00 } //01 00 
		$a_01_5 = {6d 69 6e 79 6d 65 6d 2e 65 78 65 00 } //01 00 
		$a_01_6 = {73 63 68 6f 76 6c 6f 6f 6b 2e 65 78 65 00 } //01 00 
		$a_00_7 = {6c 69 76 65 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}