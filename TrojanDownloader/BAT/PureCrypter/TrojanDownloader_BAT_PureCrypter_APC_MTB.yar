
rule TrojanDownloader_BAT_PureCrypter_APC_MTB{
	meta:
		description = "TrojanDownloader:BAT/PureCrypter.APC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 6b 00 00 70 28 1f 00 00 06 13 01 38 00 00 00 00 28 14 00 00 0a 11 01 28 21 00 00 06 72 b1 00 00 70 7e 15 00 00 0a 6f 16 00 00 0a 28 22 00 00 06 13 03 } //1
		$a_03_1 = {20 00 0c 00 00 28 ?? ?? ?? 06 38 00 00 00 00 dd 10 00 00 00 26 38 00 00 00 00 dd 05 00 00 00 38 00 00 00 00 02 28 ?? ?? ?? 0a 74 17 00 00 01 6f ?? ?? ?? 0a 73 1a 00 00 0a 13 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}