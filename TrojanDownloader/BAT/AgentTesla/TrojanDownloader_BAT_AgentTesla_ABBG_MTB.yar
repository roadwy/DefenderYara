
rule TrojanDownloader_BAT_AgentTesla_ABBG_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 0c 16 0d 08 12 03 28 90 01 03 0a 06 02 07 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 6f 90 01 03 0a de 0a 09 2c 06 08 28 90 01 03 0a dc 07 18 58 0b 07 02 6f 90 01 03 0a 32 c6 06 6f 90 01 03 0a 2a 90 00 } //5
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}