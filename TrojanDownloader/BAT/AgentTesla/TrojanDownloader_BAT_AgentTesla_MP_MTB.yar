
rule TrojanDownloader_BAT_AgentTesla_MP_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5d 13 05 11 09 09 94 13 07 11 09 09 11 09 11 05 94 9e 11 09 11 05 11 07 9e 11 09 11 09 09 94 11 09 11 05 94 58 } //1
		$a_01_1 = {5d 94 13 06 08 11 04 07 11 04 91 11 06 61 d2 9c 11 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}