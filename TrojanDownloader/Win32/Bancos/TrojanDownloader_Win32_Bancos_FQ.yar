
rule TrojanDownloader_Win32_Bancos_FQ{
	meta:
		description = "TrojanDownloader:Win32/Bancos.FQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {68 6f 6d 65 72 6f 66 6f 6e 73 65 63 61 2e 30 37 2e 73 69 74 65 73 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 2f [0-08] 2e 6a 70 67 } //1
		$a_00_1 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 20 00 43 00 68 00 72 00 6f 00 6d 00 65 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}