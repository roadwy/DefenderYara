
rule TrojanDownloader_Win32_Banload_AAD{
	meta:
		description = "TrojanDownloader:Win32/Banload.AAD,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {8a 54 3a ff 8b 4d fc 8a 4c 31 ff 32 d1 e8 } //2
		$a_01_1 = {46 4b 75 d6 8d 45 fc 8b 55 f4 e8 } //2
		$a_01_2 = {85 c0 76 07 8b 45 fc 8a 18 eb 02 33 db 33 c0 5a 59 59 64 89 10 68 } //2
		$a_01_3 = {63 6d 64 20 2f 6b 20 00 ff ff ff ff 09 00 00 00 3a 5c 77 69 6e 64 6f 77 73 } //2
		$a_01_4 = {6c 65 6f 63 61 6c 6f 74 65 69 72 6f } //1 leocaloteiro
		$a_01_5 = {6a 76 76 72 38 2d 2d } //1 jvvr8--
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}