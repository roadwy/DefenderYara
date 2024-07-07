
rule Trojan_BAT_AgentTesla_MBYL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBYL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5f 6a 61 d2 9c } //1
		$a_01_1 = {45 00 53 00 48 00 30 00 47 00 38 00 41 00 37 00 33 00 53 00 42 00 41 00 47 00 37 00 38 00 47 00 4e 00 39 00 5a 00 5a 00 48 00 34 00 } //1 ESH0G8A73SBAG78GN9ZZH4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}