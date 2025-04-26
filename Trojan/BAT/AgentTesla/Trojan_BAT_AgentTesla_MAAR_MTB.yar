
rule Trojan_BAT_AgentTesla_MAAR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MAAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 00 37 00 45 00 79 00 66 00 35 00 49 00 4e 00 49 00 6e 00 61 00 62 00 72 00 44 00 46 00 68 00 48 00 45 00 2e 00 63 00 31 00 36 00 49 00 6b 00 30 00 32 00 4b 00 53 00 77 00 4c 00 6d 00 71 00 6f 00 42 00 46 00 44 00 79 00 } //1 F7Eyf5INInabrDFhHE.c16Ik02KSwLmqoBFDy
		$a_01_1 = {41 00 41 00 00 05 42 00 42 } //1
		$a_01_2 = {4c 00 69 00 75 00 } //1 Liu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}