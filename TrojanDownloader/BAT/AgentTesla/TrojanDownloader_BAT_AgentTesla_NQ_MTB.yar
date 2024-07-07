
rule TrojanDownloader_BAT_AgentTesla_NQ_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.NQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 05 00 00 0a 0c 00 07 16 73 06 00 00 0a 73 07 00 00 0a 0d 00 09 08 6f 08 00 00 0a 00 00 de 0b } //1
		$a_01_1 = {95 a2 29 09 0b 00 00 00 da a4 21 00 16 00 00 01 00 00 00 39 00 00 00 08 00 00 00 06 00 00 00 12 00 00 00 04 00 00 00 39 00 00 00 18 00 00 00 01 00 00 00 07 00 00 00 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}