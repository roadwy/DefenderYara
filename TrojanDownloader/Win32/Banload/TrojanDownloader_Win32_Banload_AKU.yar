
rule TrojanDownloader_Win32_Banload_AKU{
	meta:
		description = "TrojanDownloader:Win32/Banload.AKU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3c 4d 75 07 80 fb 48 75 02 b0 4e 8b d8 25 ff 00 00 00 83 c0 de 83 f8 38 0f 87 ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? ff 24 85 } //1
		$a_03_1 = {8b 0e 8b 1f 38 d9 75 ?? 4a 74 ?? 38 fd 75 ?? 4a 74 ?? 81 e3 00 00 ff 00 81 e1 00 00 ff 00 39 d9 75 } //1
		$a_00_2 = {47 52 41 4e 44 45 20 4d 45 44 49 4f 20 44 49 52 45 54 41 53 } //1 GRANDE MEDIO DIRETAS
		$a_00_3 = {49 45 28 41 4c 28 22 25 73 22 2c 34 29 2c 22 41 4c 28 5c 22 25 30 3a 73 5c 22 2c 33 29 22 2c 22 4a 4b 28 5c 22 25 31 3a 73 5c 22 2c 5c 22 25 30 3a 73 5c 22 29 22 29 } //1 IE(AL("%s",4),"AL(\"%0:s\",3)","JK(\"%1:s\",\"%0:s\")")
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}