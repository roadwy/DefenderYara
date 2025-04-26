
rule TrojanDownloader_BAT_CryptInject_BA_MTB{
	meta:
		description = "TrojanDownloader:BAT/CryptInject.BA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 00 6f 00 73 00 74 00 75 00 72 00 61 00 2e 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 69 00 6e 00 66 00 2e 00 64 00 6c 00 6c 00 2e 00 7a 00 69 00 70 00 } //1 costura.system.inf.dll.zip
		$a_01_1 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 00 45 6e 64 73 57 69 74 68 00 47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d 00 43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}