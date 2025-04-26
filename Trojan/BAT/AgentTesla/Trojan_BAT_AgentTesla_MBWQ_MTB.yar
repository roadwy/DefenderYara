
rule Trojan_BAT_AgentTesla_MBWQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 1f 10 8d ?? 00 00 01 0c 07 08 6f ?? 00 00 0a 00 02 03 04 6f ?? 00 00 0a 0d de 0b } //2
		$a_01_1 = {43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}