
rule TrojanDownloader_BAT_Nijrecy_A{
	meta:
		description = "TrojanDownloader:BAT/Nijrecy.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 0c 11 10 20 00 30 00 00 1f 40 28 ?? ?? ?? ?? 13 0d 11 04 16 8f ?? ?? ?? ?? 71 ?? ?? ?? ?? 11 0d 02 11 05 28 ?? ?? ?? ?? b8 11 0e 28 } //2
		$a_01_1 = {50 48 50 20 43 72 79 70 74 65 72 } //1 PHP Crypter
		$a_01_2 = {5b 00 23 00 23 00 5d 00 } //1 [##]
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}