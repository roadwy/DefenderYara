
rule TrojanSpy_BAT_AgentTesla_AA_MTB{
	meta:
		description = "TrojanSpy:BAT/AgentTesla.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 04 16 13 05 2b 37 11 04 11 05 9a 13 06 09 72 bc 06 00 70 11 06 07 11 06 6f 36 00 00 0a 28 10 00 00 0a 28 37 00 00 0a 72 77 00 00 70 28 14 00 00 0a 28 15 00 00 0a 0d 11 05 17 d6 13 05 11 05 11 04 8e 69 32 c1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}