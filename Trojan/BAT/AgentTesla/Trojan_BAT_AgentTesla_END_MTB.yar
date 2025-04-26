
rule Trojan_BAT_AgentTesla_END_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.END!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 11 04 91 11 01 61 11 09 11 03 91 61 13 05 20 03 00 00 00 28 ?? ?? ?? 06 } //1
		$a_01_1 = {02 02 8e 69 17 59 91 1f 70 61 13 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}