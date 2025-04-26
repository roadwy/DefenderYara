
rule TrojanDownloader_BAT_AgentTesla_KA_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 08 13 06 16 13 07 11 06 12 07 28 1e 00 00 0a 00 08 07 11 05 18 6f 1f 00 00 0a 1f 10 28 20 00 00 0a 6f 21 00 00 0a 00 de 0d 11 07 2c 08 11 06 28 22 00 00 0a 00 dc } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule TrojanDownloader_BAT_AgentTesla_KA_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 72 ?? ?? ?? 70 73 ?? ?? ?? 0a a2 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 0b 07 8e } //1
		$a_01_1 = {48 74 74 70 43 6c 69 65 6e 74 } //1 HttpClient
		$a_01_2 = {41 64 64 52 61 6e 67 65 } //1 AddRange
		$a_01_3 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}