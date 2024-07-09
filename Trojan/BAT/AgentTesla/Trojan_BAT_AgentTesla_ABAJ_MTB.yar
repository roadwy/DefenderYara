
rule Trojan_BAT_AgentTesla_ABAJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 08 18 5b 02 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 08 18 58 0c 08 06 32 e4 07 2a } //3
		$a_01_1 = {52 00 78 00 6e 00 69 00 71 00 76 00 74 00 62 00 63 00 79 00 74 00 72 00 6f 00 70 00 6a 00 6b 00 6f 00 66 00 2e 00 46 00 78 00 72 00 67 00 78 00 75 00 63 00 7a 00 66 00 6c 00 63 00 72 00 7a 00 64 00 76 00 } //1 Rxniqvtbcytropjkof.Fxrgxuczflcrzdv
		$a_01_2 = {41 00 67 00 75 00 71 00 62 00 6c 00 65 00 74 00 66 00 75 00 73 00 } //1 Aguqbletfus
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}