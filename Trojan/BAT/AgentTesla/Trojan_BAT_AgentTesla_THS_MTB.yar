
rule Trojan_BAT_AgentTesla_THS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.THS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0d 09 09 47 02 08 1f 10 5d 91 61 d2 52 } //1
		$a_01_1 = {08 17 d6 0c 08 07 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}