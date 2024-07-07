
rule TrojanDownloader_BAT_StealC_ASE_MTB{
	meta:
		description = "TrojanDownloader:BAT/StealC.ASE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {17 da 0b 16 0c 2b 15 02 08 02 08 9a 03 72 6b 02 00 70 6f 74 00 00 0a a2 08 17 d6 0c 08 07 31 e7 } //1
		$a_01_1 = {25 16 07 a2 25 0c 14 14 17 8d 68 00 00 01 25 16 17 9c 25 0d 17 28 70 00 00 0a 26 09 16 91 2d 02 2b 1d 08 16 9a 28 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}