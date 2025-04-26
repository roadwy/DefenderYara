
rule TrojanDownloader_BAT_CryptInject_AC_MTB{
	meta:
		description = "TrojanDownloader:BAT/CryptInject.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 9a 13 06 02 fe 06 1c 00 00 06 73 58 00 00 0a 73 59 00 00 0a 13 07 11 07 06 72 45 02 00 70 11 06 28 5a 00 00 0a 6f 5b 00 00 0a 00 00 11 05 17 d6 13 05 11 05 11 04 8e 69 fe 04 13 08 11 08 2d bc } //2
		$a_01_1 = {61 00 76 00 6f 00 63 00 61 00 64 00 6f 00 2e 00 65 00 78 00 65 00 } //1 avocado.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}