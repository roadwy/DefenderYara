
rule TrojanDownloader_Linux_Ledod_L{
	meta:
		description = "TrojanDownloader:Linux/Ledod.L,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {73 75 6b 61 20 3d 20 22 68 74 74 70 3a 2f 2f 90 02 60 2e 65 78 65 22 90 00 } //1
		$a_01_1 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 73 75 6b 61 2c 20 46 61 6c 73 65 } //1 .Open "GET", suka, False
		$a_01_2 = {53 65 74 20 58 32 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 64 6f 64 62 2e 53 74 72 65 61 6d 22 29 } //1 Set X2 = CreateObject("Adodb.Stream")
		$a_03_3 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 90 02 10 20 26 20 22 5c 90 02 10 2e 63 6f 6d 22 2c 20 32 90 00 } //1
		$a_01_4 = {2e 52 75 6e 20 28 53 75 6b 61 } //1 .Run (Suka
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}