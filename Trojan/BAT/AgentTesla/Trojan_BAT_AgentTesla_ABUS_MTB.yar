
rule Trojan_BAT_AgentTesla_ABUS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABUS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {18 da 13 18 16 13 19 2b 23 07 08 06 11 19 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a b4 6f 90 01 01 00 00 0a 00 08 17 d6 0c 11 19 18 d6 13 19 11 19 11 18 31 d7 90 00 } //4
		$a_01_1 = {43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 5f 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Cookies_Project.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}