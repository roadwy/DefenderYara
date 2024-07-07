
rule Trojan_BAT_AgentTesla_EAB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 09 5a 20 ff 00 00 00 5d 1f 14 11 09 5a 20 ff 00 00 00 5d 20 96 00 00 00 11 09 5a 20 ff 00 00 00 5d 28 } //2
		$a_03_1 = {09 11 06 08 11 06 9a 7b 90 01 01 00 00 04 a1 00 11 06 17 58 13 06 11 06 03 6f 90 01 01 00 00 0a fe 04 13 07 11 07 90 00 } //2
		$a_01_2 = {72 00 61 00 64 00 61 00 72 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 radarsystem.Properties.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}