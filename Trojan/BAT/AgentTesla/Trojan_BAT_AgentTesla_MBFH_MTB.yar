
rule Trojan_BAT_AgentTesla_MBFH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 13 0b 07 11 04 91 13 0c 07 11 04 11 0c 11 06 06 1f 16 5d 91 61 11 0b 59 20 00 01 00 00 5d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}