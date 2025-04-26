
rule TrojanDownloader_Win32_Banload_XH{
	meta:
		description = "TrojanDownloader:Win32/Banload.XH,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 } //1 \Software\Microsoft\Security Center
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 49 43 52 4f 53 4f 46 54 5c 57 49 4e 44 4f 57 53 5c 43 55 52 52 45 4e 54 56 45 52 53 49 4f 4e 5c 52 55 4e } //1 SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN
		$a_01_2 = {45 72 72 6f 20 61 6f 20 61 62 72 69 72 20 6f 20 61 72 71 75 69 76 6f 2c 6f 75 20 6f 20 61 72 71 75 69 76 6f 20 65 73 74 61 20 63 6f 72 72 6f 6d 70 69 64 6f } //4 Erro ao abrir o arquivo,ou o arquivo esta corrompido
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*4) >=6
 
}