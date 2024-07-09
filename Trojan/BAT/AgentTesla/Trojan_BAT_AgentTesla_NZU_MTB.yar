
rule Trojan_BAT_AgentTesla_NZU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 06 8e 69 5d 06 08 06 8e 69 5d 91 07 08 1f 16 5d 91 61 28 ?? ?? ?? 0a 06 08 17 58 06 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 } //10
		$a_81_1 = {43 38 41 45 44 48 41 55 56 48 37 35 49 34 37 52 52 37 52 44 35 48 } //1 C8AEDHAUVH75I47RR7RD5H
		$a_81_2 = {4a 45 50 34 35 57 4a 38 45 39 5a 37 48 37 37 35 34 38 37 4a 51 38 } //1 JEP45WJ8E9Z7H775487JQ8
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=11
 
}