
rule TrojanDownloader_BAT_Ader_ABSB_MTB{
	meta:
		description = "TrojanDownloader:BAT/Ader.ABSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 2d 04 2b 24 2b 29 1a 2c 1d 7e ?? 00 00 04 7e ?? 00 00 04 7e ?? 00 00 04 2b 18 2b 1d 2b 1e 2b 23 2b 28 2b 2d 2b 32 de 39 28 ?? 00 00 06 2b d5 0a 2b d4 28 ?? 00 00 06 2b e1 06 2b e0 28 ?? 00 00 06 2b db 28 ?? 00 00 06 2b d6 28 ?? 00 00 2b 2b d1 28 ?? 00 00 2b 2b cc 0b 2b cb } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}