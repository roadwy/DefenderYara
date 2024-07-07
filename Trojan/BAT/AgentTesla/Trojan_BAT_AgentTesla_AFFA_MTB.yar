
rule Trojan_BAT_AgentTesla_AFFA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AFFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1e fe 0f e0 38 a8 00 00 00 38 a9 00 00 00 16 54 38 a8 00 00 00 38 ad 00 00 00 38 ae 00 00 00 38 b3 00 00 00 38 b4 00 00 00 1a 58 16 54 38 b1 00 00 00 1a 58 16 54 2b 52 38 ac 00 00 00 06 1a 58 4a 03 8e 69 5d 03 06 1a 58 4a 03 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 90 01 03 0a 03 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}