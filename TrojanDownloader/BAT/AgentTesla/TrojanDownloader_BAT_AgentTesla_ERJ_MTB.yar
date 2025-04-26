
rule TrojanDownloader_BAT_AgentTesla_ERJ_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ERJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 07 06 08 91 6f ?? ?? ?? 0a 00 00 08 25 17 59 0c 16 fe 02 0d 09 } //1
		$a_03_1 = {20 00 0c 00 00 28 ?? ?? ?? 0a 00 00 de 05 26 00 00 de 00 73 ?? ?? ?? 0a 03 73 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 2b 00 06 2a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}