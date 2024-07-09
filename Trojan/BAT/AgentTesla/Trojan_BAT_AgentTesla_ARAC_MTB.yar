
rule Trojan_BAT_AgentTesla_ARAC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 8e 69 8d ?? ?? ?? 01 0b 16 0c 06 8e 69 17 59 0d 38 ?? ?? ?? 00 07 08 06 09 91 9c 08 17 58 0c 09 17 59 0d 09 16 2f ee } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}