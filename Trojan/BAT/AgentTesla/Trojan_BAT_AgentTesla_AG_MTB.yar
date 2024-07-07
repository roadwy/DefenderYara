
rule Trojan_BAT_AgentTesla_AG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 07 19 95 37 03 16 2b 01 17 17 59 7e 07 00 00 04 18 9a 20 58 03 00 00 95 5f 7e 07 00 00 04 18 9a 20 f6 01 00 00 95 61 61 81 05 00 00 01 } //2
		$a_01_1 = {18 9a 20 d6 02 00 00 95 61 81 05 00 00 01 38 99 01 00 00 7e 2d 00 00 04 1f 1b 95 7e 07 00 00 04 18 9a 20 5c 01 00 00 95 33 3b } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}