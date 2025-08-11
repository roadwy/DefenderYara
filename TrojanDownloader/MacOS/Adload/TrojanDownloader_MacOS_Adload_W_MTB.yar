
rule TrojanDownloader_MacOS_Adload_W_MTB{
	meta:
		description = "TrojanDownloader:MacOS/Adload.W!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 81 fe fe ff ff 7f ba fe ff ff 7f 49 0f 42 d6 bf 02 00 00 00 4c 89 fe e8 80 68 00 00 48 83 f8 ff 74 ca 48 85 c0 74 15 4c 89 f1 48 29 c1 72 28 49 01 c7 49 89 ce 4d 85 f6 } //1
		$a_01_1 = {55 48 89 e5 53 50 48 89 fb 48 81 f9 00 04 00 00 b8 00 04 00 00 48 0f 42 c1 bf 02 00 00 00 48 89 d6 89 c2 e8 2e 69 00 00 48 83 f8 ff 74 08 48 89 43 08 31 c0 eb 18 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}