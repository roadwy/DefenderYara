
rule TrojanDownloader_Win32_Bancos_DA{
	meta:
		description = "TrojanDownloader:Win32/Bancos.DA,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 6f 76 69 64 61 64 65 73 6c 6f 75 63 61 73 2e 6e 6f 2d 69 70 2e 69 6e 66 6f } //1 novidadesloucas.no-ip.info
		$a_01_1 = {69 6e 64 65 66 69 6e 69 64 6f } //1 indefinido
		$a_01_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_01_3 = {65 73 6d 61 73 6d 61 73 6b 73 } //1 esmasmasks
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}