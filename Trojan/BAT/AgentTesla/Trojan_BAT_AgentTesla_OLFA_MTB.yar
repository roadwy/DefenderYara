
rule Trojan_BAT_AgentTesla_OLFA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OLFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 47 06 07 06 8e 69 5d 91 07 1f 63 58 06 8e 69 58 1f 1f 5f 63 d2 61 d2 52 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}