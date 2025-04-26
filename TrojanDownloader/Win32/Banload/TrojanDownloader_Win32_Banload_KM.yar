
rule TrojanDownloader_Win32_Banload_KM{
	meta:
		description = "TrojanDownloader:Win32/Banload.KM,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5f 32 72 65 6c 72 66 6b 73 61 64 76 } //1 _2relrfksadv
		$a_01_1 = {4d 65 6e 73 61 67 65 6e 73 20 64 65 20 65 72 72 6f } //1 Mensagens de erro
		$a_01_2 = {61 72 71 75 69 76 6f 62 6f 6c } //1 arquivobol
		$a_01_3 = {47 62 50 6c 75 67 69 6e 2e 65 78 65 } //1 GbPlugin.exe
		$a_01_4 = {2f 45 78 70 6c 6f 72 65 72 2e 6a 73 } //1 /Explorer.js
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}