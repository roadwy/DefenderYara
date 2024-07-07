
rule Trojan_BAT_AgentTesla_PTGZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTGZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 08 00 00 0a 72 61 00 00 70 28 90 01 01 00 00 0a 0d 09 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 0d dd 06 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}