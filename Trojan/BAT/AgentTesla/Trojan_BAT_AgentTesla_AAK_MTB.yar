
rule Trojan_BAT_AgentTesla_AAK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 17 0d 00 06 07 25 17 58 0b 08 9e 00 08 17 58 0c 00 07 03 fe 04 13 04 11 04 2d e4 } //2
		$a_81_1 = {24 35 39 62 64 39 63 65 30 2d 35 63 32 62 2d 34 36 33 65 2d 39 38 61 39 2d 34 32 30 34 32 39 64 30 63 38 63 35 } //2 $59bd9ce0-5c2b-463e-98a9-420429d0c8c5
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}