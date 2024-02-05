
rule Trojan_BAT_AgentTesla_AER_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8e 69 17 da 91 1f 70 61 90 01 0a 8e 69 17 d6 17 da 17 d6 90 01 0a 02 8e 69 17 25 2c 56 da 13 04 11 04 13 05 16 25 2d dd 13 06 2b 43 09 11 06 02 11 06 91 08 61 07 11 07 91 61 b4 9c 11 07 03 90 00 } //02 00 
		$a_80_1 = {47 65 74 4d 65 74 68 6f 64 73 } //GetMethods  02 00 
		$a_80_2 = {47 65 74 54 79 70 65 73 } //GetTypes  02 00 
		$a_80_3 = {43 61 6c 6c 42 79 4e 61 6d 65 } //CallByName  00 00 
	condition:
		any of ($a_*)
 
}