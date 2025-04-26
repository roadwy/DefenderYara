
rule Trojan_BAT_AgentTesla_MBZO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 08 06 08 91 20 00 01 00 00 59 03 08 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 58 20 00 01 00 00 5d d2 9c 00 08 17 58 0c 08 06 8e 69 } //1
		$a_01_1 = {59 00 61 00 68 00 65 00 48 00 61 00 74 00 2e 00 65 00 78 00 65 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}