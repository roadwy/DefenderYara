
rule Trojan_BAT_AgentTesla_ABMO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 07 09 11 07 9a 1f 10 28 90 01 01 00 00 0a 9c 00 11 07 17 58 13 07 11 07 09 8e 69 fe 04 13 08 11 08 2d db 90 00 } //5
		$a_01_1 = {53 00 69 00 6d 00 75 00 6c 00 61 00 74 00 65 00 75 00 72 00 5f 00 64 00 65 00 73 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Simulateur_des.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}