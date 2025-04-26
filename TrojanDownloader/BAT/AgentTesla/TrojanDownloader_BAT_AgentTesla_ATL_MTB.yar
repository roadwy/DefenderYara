
rule TrojanDownloader_BAT_AgentTesla_ATL_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ATL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0a 06 18 5b 8d 32 00 00 01 0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f 43 00 00 0a 1f 10 28 44 00 00 0a 9c 08 18 58 0c 08 06 32 e4 } //2
		$a_01_1 = {74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 2e 00 73 00 68 00 } //1 transfer.sh
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}