
rule Trojan_BAT_AgentTesla_PSNW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {14 0a 38 2c 00 00 00 00 28 90 01 03 0a 02 72 01 00 00 70 28 90 01 03 06 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 06 0a dd 06 00 00 00 26 dd 00 00 00 00 06 2c d1 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}