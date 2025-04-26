
rule Trojan_BAT_AgentTesla_MBBW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 00 7d 00 3a 00 3a 00 3a 00 7c 00 7d 00 32 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 7c 00 7d 00 33 00 3a 00 7c 00 34 00 7d 00 7c 00 38 00 35 00 3a 00 3a 00 7c 00 31 00 7d 00 3a 00 3a 00 } //1 E}:::|}2::::::|}3:|4}|85::|1}::
		$a_01_1 = {34 00 44 00 7c 00 35 00 41 00 7c 00 39 00 7d 00 3a 00 7c 00 7d 00 33 00 3a 00 3a 00 3a 00 7c 00 7d 00 34 00 3a 00 3a 00 3a 00 7c 00 46 00 46 00 7c 00 46 00 46 00 3a 00 3a 00 7c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}