
rule TrojanDownloader_Win32_Bancos_DJ{
	meta:
		description = "TrojanDownloader:Win32/Bancos.DJ,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {41 42 52 41 20 20 45 4d 20 4f 55 54 52 4f 20 43 4f 4d 50 55 54 41 44 4f 52 21 21 00 } //3 䉁䅒†䵅传呕佒䌠䵏啐䅔佄⅒!
		$a_01_1 = {6f 6c 68 61 6d 69 6e 68 61 66 6f 74 6f 73 2e 68 70 67 2e 63 6f 6d 2e 62 72 2f } //1 olhaminhafotos.hpg.com.br/
		$a_01_2 = {62 72 2f 68 6f 74 6d 61 69 6c 2e 6a 70 67 } //1 br/hotmail.jpg
		$a_01_3 = {63 6f 6d 75 6e 73 5c 68 6f 74 6d 61 69 6c 2e 65 78 65 } //1 comuns\hotmail.exe
		$a_01_4 = {62 72 2f 67 64 62 72 72 2e 6a 70 67 } //1 br/gdbrr.jpg
		$a_01_5 = {63 6f 6d 75 6e 73 5c 67 64 62 72 72 2e 65 78 65 } //1 comuns\gdbrr.exe
		$a_01_6 = {62 72 2f 73 61 74 70 6c 67 2e 6a 70 67 } //1 br/satplg.jpg
		$a_01_7 = {63 6f 6d 75 6e 73 5c 73 61 74 70 6c 67 2e 65 78 65 } //1 comuns\satplg.exe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}