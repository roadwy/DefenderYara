
rule Trojan_BAT_AgentTesla_CCDS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CCDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 04 5d 13 0d 11 06 11 05 5d 13 0e 11 06 17 58 11 04 5d 13 0f 07 11 0d 91 13 10 20 ?? ?? ?? ?? 13 11 11 10 08 11 0e 91 61 07 11 0f 91 59 11 11 58 11 11 5d 13 12 07 11 0d 11 12 d2 9c 11 06 17 58 13 06 00 11 06 11 04 09 17 58 5a fe 04 13 13 11 13 2d a9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}