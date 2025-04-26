
rule Trojan_BAT_AgentTesla_MBAX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 11 08 08 11 08 9a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 08 17 58 13 08 11 08 08 8e 69 fe 04 13 09 11 09 2d d9 } //1
		$a_01_1 = {72 01 03 00 70 72 05 03 00 70 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}