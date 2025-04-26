
rule TrojanDownloader_BAT_AveMariaRAT_I_MTB{
	meta:
		description = "TrojanDownloader:BAT/AveMariaRAT.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 0b 2b 2e 16 2b 2e 2b 33 2b 38 16 2d 09 2b 09 2b 0a 6f ?? 00 00 0a de 10 08 2b f4 07 2b f3 08 2c 06 08 6f ?? 00 00 0a dc 07 6f ?? 00 00 0a 0d de 2e 06 2b cf 73 ?? 00 00 0a 2b cb 73 } //2
		$a_03_1 = {0a 0a 1c 2c 08 2b 08 2b 09 2b 0a 2b 0f de 23 06 2b f5 02 2b f4 6f ?? 00 00 0a 2b ef 0b 2b ee } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}