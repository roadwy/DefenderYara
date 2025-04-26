
rule Trojan_BAT_AgentTesla_EYK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 00 7e 00 7e 00 7e 00 4b 00 7e 00 43 00 70 00 69 00 7e 00 67 00 51 00 6f 00 4c 00 67 00 7e 00 7e 00 42 00 67 00 7e 00 7e 00 7e 00 67 00 4e 00 39 00 7e 00 67 00 7e 00 } //1 I~~~K~Cpi~gQoLg~~Bg~~~gN9~g~
		$a_01_1 = {54 00 4d 00 7e 00 49 00 7e 00 44 00 51 00 7e 00 7e 00 7e 00 7e 00 4d 00 7e 00 7e 00 42 00 45 00 7e 00 7e 00 67 00 4d 00 6f 00 47 00 51 00 7e 00 7e 00 43 00 67 00 } //1 TM~I~DQ~~~~M~~BE~~gMoGQ~~Cg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}