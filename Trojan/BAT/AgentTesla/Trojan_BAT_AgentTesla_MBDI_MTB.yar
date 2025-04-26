
rule Trojan_BAT_AgentTesla_MBDI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 35 00 41 00 39 00 5e 00 5e 00 5e 00 5e 00 33 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 34 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 51 00 51 00 51 00 51 00 5e 00 5e 00 5e 00 5e 00 42 00 38 00 5e 00 5e 00 } //1 4D5A9^^^^3^^^^^^^4^^^^^^QQQQ^^^^B8^^
		$a_01_1 = {5e 00 45 00 31 00 51 00 42 00 41 00 5e 00 45 00 5e 00 5e 00 42 00 34 00 5e 00 39 00 43 00 44 00 32 00 31 00 42 00 38 00 5e 00 31 00 } //1 ^E1QBA^E^^B4^9CD21B8^1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}