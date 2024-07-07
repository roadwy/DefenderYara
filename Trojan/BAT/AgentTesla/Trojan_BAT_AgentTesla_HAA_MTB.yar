
rule Trojan_BAT_AgentTesla_HAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {18 2c 10 2b 10 2b 15 2b 1a 2b 1f 16 2c 03 26 de 26 2b 1e 2b fa 28 90 01 01 00 00 0a 2b e9 28 90 01 01 00 00 06 2b e4 6f 90 01 01 00 00 0a 2b df 28 90 01 01 00 00 0a 2b da 0a 2b df 90 00 } //2
		$a_03_1 = {06 08 09 9c 07 17 58 0b 08 17 59 0c 16 2d d4 07 08 32 e0 06 2a 0a 38 90 01 01 ff ff ff 06 2b bb 06 2b c4 0c 2b ca 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}