
rule Trojan_BAT_AgentTesla_HC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {08 84 95 9e 11 05 08 84 11 06 9e 09 06 28 90 01 04 03 06 28 90 01 04 91 11 05 11 05 07 84 95 11 05 08 84 95 d7 6e 20 90 01 04 6a 5f b7 95 61 86 9c 06 11 09 12 00 28 90 01 04 2d 94 90 00 } //10
		$a_80_1 = {50 72 6f 70 65 72 5f 52 43 34 } //Proper_RC4  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}