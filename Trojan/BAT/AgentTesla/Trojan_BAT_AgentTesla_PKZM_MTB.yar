
rule Trojan_BAT_AgentTesla_PKZM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PKZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 3c 00 00 0a 72 15 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 17 } //3
		$a_03_1 = {43 00 00 0a 0c 08 06 6f ?? 00 00 0a 08 07 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 73 47 00 00 0a 25 09 03 16 03 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}