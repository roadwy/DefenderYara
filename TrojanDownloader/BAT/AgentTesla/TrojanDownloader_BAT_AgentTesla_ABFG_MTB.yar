
rule TrojanDownloader_BAT_AgentTesla_ABFG_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {2b 0d 2b 0f 18 2b 10 1f 10 2b 10 2b 12 de 35 2b 11 2b ef 2b 10 2b ed 2b 0f 2b ec 2b 12 2b ec 0a 2b eb 02 2b ec 03 2b ed 6f 90 01 03 0a 2b ea 28 90 01 03 0a 2b e7 90 00 } //2
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_3 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}