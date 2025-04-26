
rule Trojan_BAT_AgentTesla_AAEY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 22 11 05 11 06 18 6f ?? 00 00 0a 13 0c 11 07 11 06 18 5b 11 0c 1f 10 28 ?? 00 00 0a 9c 11 06 18 58 13 06 11 06 11 05 6f ?? 00 00 0a fe 04 13 0d 11 0d 2d cd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}