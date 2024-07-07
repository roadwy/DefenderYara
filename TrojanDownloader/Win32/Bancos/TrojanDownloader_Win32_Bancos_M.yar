
rule TrojanDownloader_Win32_Bancos_M{
	meta:
		description = "TrojanDownloader:Win32/Bancos.M,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 76 63 68 6f 73 74 2e 65 78 65 00 } //2
		$a_01_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 77 73 63 74 79 33 32 2e 65 78 65 00 } //2
		$a_01_2 = {30 30 31 2e 6a 70 67 00 } //1 〰⸱灪g
		$a_01_3 = {30 30 32 2e 6a 70 67 00 } //1 〰⸲灪g
		$a_03_4 = {84 c0 74 30 6a 00 68 90 01 02 45 00 e8 90 01 02 fb ff ba 90 01 02 45 00 b8 90 01 02 45 00 e8 90 01 02 ff ff 84 c0 74 0c 90 00 } //5
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*5) >=8
 
}