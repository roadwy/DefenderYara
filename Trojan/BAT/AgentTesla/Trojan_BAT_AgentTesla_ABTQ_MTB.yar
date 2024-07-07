
rule Trojan_BAT_AgentTesla_ABTQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABTQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 06 16 73 90 01 01 00 00 0a 73 90 01 01 00 00 0a 0c 08 07 6f 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 0d de 1e 08 2c 06 08 6f 90 01 01 00 00 0a dc 90 00 } //4
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 31 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 WindowsFormsApp1.Properties.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}