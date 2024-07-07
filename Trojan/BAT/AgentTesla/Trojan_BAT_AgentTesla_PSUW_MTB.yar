
rule Trojan_BAT_AgentTesla_PSUW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSUW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 28 16 00 00 0a 03 6f 17 00 00 0a 0a 02 02 8e 69 17 59 91 1f 70 61 0b 02 8e 69 8d 32 00 00 01 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}