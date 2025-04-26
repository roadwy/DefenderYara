
rule TrojanDownloader_Win32_Banload_BAD{
	meta:
		description = "TrojanDownloader:Win32/Banload.BAD,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 68 69 67 68 73 6c 69 64 65 2f 67 72 61 70 68 69 63 73 2f 6f 75 74 6c 69 6e 65 73 2f 69 6e 74 74 2f 6e 66 65 2f 6e 66 65 2e 72 61 72 } //5 /highslide/graphics/outlines/intt/nfe/nfe.rar
		$a_01_1 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 } //1 \Software\Microsoft\Security Center
		$a_01_2 = {46 61 6c 68 61 20 61 6f 20 61 62 72 69 72 20 6f 20 61 72 71 75 69 76 6f 20 6f 75 20 6f 20 61 72 71 75 69 76 6f 20 65 73 74 } //1 Falha ao abrir o arquivo ou o arquivo est
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}