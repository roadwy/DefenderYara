
rule Trojan_BAT_AgentTesla_MBFX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 11 04 09 6f 90 01 01 00 00 0a 13 05 08 11 04 09 11 05 90 00 } //1
		$a_01_1 = {70 61 74 68 6f 6c 6f 67 69 73 74 2e 64 } //1 pathologist.d
		$a_01_2 = {38 32 33 34 42 31 32 31 38 34 32 42 } //1 8234B121842B
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}