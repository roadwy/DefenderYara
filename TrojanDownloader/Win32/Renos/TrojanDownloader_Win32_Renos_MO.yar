
rule TrojanDownloader_Win32_Renos_MO{
	meta:
		description = "TrojanDownloader:Win32/Renos.MO,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8d 4d 0c 6a 04 51 6a 04 53 50 ff b6 a0 00 00 00 ff 15 } //1
		$a_01_1 = {53 68 00 00 08 84 56 53 50 ff 75 e8 ff 15 } //1
		$a_01_2 = {8d 8d 50 ff ff ff 51 53 ff 75 cc 50 ff 15 } //1
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4a 44 4b 35 53 57 46 4d 5a 59 00 } //1 潓瑦慷敲䩜䭄匵䙗婍Y
		$a_01_4 = {67 6f 6f 67 6c 65 2e 63 6f 6d 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}