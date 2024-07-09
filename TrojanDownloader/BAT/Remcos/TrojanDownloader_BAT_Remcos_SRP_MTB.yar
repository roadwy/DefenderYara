
rule TrojanDownloader_BAT_Remcos_SRP_MTB{
	meta:
		description = "TrojanDownloader:BAT/Remcos.SRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 1a 13 04 2b f1 06 07 6f ?? ?? ?? 0a 13 05 11 04 11 05 6f ?? ?? ?? 0a 07 17 58 0b 07 06 6f ?? ?? ?? 0a 32 e1 14 11 04 28 ?? ?? ?? 2b 0a de 17 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}