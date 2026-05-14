
rule TrojanDownloader_BAT_AgentTesla_CA_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 91 06 61 20 ?? ?? ?? ?? 61 d2 9c 06 17 58 0a 06 7e ?? ?? ?? ?? 8e 69 fe 04 2d d9 } //5
		$a_03_1 = {06 07 06 07 91 1f ?? 61 d2 9c 07 17 58 0b 07 06 8e 69 32 ec } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}