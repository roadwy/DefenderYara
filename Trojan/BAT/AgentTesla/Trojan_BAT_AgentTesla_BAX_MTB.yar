
rule Trojan_BAT_AgentTesla_BAX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 04 15 58 13 04 11 04 16 fe 04 16 fe 01 13 05 11 05 2d b0 } //3
		$a_01_1 = {47 00 32 00 44 00 35 00 48 00 37 00 52 00 35 00 45 00 52 00 34 00 37 00 35 00 38 00 38 00 38 00 35 00 37 00 47 00 37 00 35 00 34 00 } //1 G2D5H7R5ER47588857G754
		$a_01_2 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}