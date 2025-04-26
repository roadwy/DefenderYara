
rule Trojan_BAT_AgentTesla_OXIE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OXIE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_02_0 = {11 07 11 08 93 28 ?? ?? ?? ?? 13 0a 11 0a 07 32 0a 11 0a 08 fe 02 16 fe 01 2b 01 16 13 0b 11 0b 2c 21 11 0a 09 fe 02 13 0c 11 0c 2c 0a 11 0a 1f 0d da 13 0a 00 2b 09 00 11 0a 1f 0d d6 13 0a 00 00 2b 38 11 0a 11 04 32 0b 11 0a 11 05 fe 02 16 fe 01 2b 01 16 13 0d 11 0d 2c 20 11 0a 11 06 fe 02 13 0e 11 0e 2c 0a 11 0a 1f 0d da 13 0a 00 2b 09 00 11 0a 1f 0d d6 13 0a 00 00 11 07 11 08 11 0a 28 ?? ?? ?? ?? 9d 11 08 17 d6 13 08 11 } //10
		$a_80_1 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //FromBase64CharArray  2
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*2) >=12
 
}