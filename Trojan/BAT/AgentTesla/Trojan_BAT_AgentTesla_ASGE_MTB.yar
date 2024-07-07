
rule Trojan_BAT_AgentTesla_ASGE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 08 11 04 5d 13 0a 11 08 17 58 11 04 5d 13 0b 07 11 0b 91 11 09 58 13 0c } //1
		$a_01_1 = {07 11 0a 91 13 0d 11 0d 08 11 08 1f 16 5d 91 61 13 0e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}