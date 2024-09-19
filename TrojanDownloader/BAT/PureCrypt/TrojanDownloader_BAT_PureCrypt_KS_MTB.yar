
rule TrojanDownloader_BAT_PureCrypt_KS_MTB{
	meta:
		description = "TrojanDownloader:BAT/PureCrypt.KS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 31 35 35 2e 39 34 2e 32 31 30 2e 37 33 2f 62 6c 65 73 73 2e 70 64 66 } //1 http://155.94.210.73/bless.pdf
		$a_01_1 = {06 72 01 00 00 70 28 29 05 00 06 6f 59 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}