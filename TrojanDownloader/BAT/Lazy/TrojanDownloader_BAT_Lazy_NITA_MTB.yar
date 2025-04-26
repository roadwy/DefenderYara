
rule TrojanDownloader_BAT_Lazy_NITA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Lazy.NITA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 72 f9 01 00 70 0a 73 34 00 00 0a 0b 73 29 00 00 0a 25 72 e9 00 00 70 6f ?? 00 00 0a 00 25 72 a0 03 00 70 06 72 b6 03 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 25 17 6f ?? 00 00 0a 00 25 17 6f ?? 00 00 0a 00 25 16 6f ?? 00 00 0a 00 25 17 6f ?? 00 00 0a 00 25 72 65 00 00 70 } //2
		$a_03_1 = {73 12 00 00 06 0a 00 06 73 2e 00 00 0a 7d 0a 00 00 04 72 af 01 00 70 02 28 ?? 00 00 2b 06 fe 06 13 00 00 06 73 30 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 73 33 00 00 0a 0b 2b 00 07 2a } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}