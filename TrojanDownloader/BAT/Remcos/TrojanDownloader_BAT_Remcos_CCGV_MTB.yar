
rule TrojanDownloader_BAT_Remcos_CCGV_MTB{
	meta:
		description = "TrojanDownloader:BAT/Remcos.CCGV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 2b 0b 72 ?? ?? ?? ?? 2b 0b 2b 10 de 2b 73 ?? ?? ?? ?? 2b ee 28 ?? 00 00 0a 2b ee 0a 2b ed 08 2c 06 08 6f ?? 00 00 0a 1d 2c f7 19 2c f1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}