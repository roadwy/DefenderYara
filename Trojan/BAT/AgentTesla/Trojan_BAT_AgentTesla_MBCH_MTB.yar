
rule Trojan_BAT_AgentTesla_MBCH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 11 05 08 11 05 9a 1f 10 28 90 01 03 0a 9c 00 11 05 17 58 13 05 11 05 08 8e 69 fe 04 13 06 11 06 2d dc 90 00 } //1
		$a_03_1 = {72 66 11 00 70 72 6a 11 00 70 6f 90 01 03 0a 0b 07 72 6e 11 00 70 72 72 11 00 70 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_MBCH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 9a 13 08 09 11 08 1f 10 28 90 01 03 0a b4 6f 90 01 03 0a 00 11 04 17 d6 13 04 00 11 04 08 8e 69 fe 04 13 09 90 00 } //1
		$a_01_1 = {34 00 44 00 5a 00 35 00 41 00 5a 00 39 00 51 00 51 00 33 00 40 00 51 00 51 00 51 00 34 00 40 00 51 00 51 00 30 00 5a 00 46 00 46 00 5a 00 46 00 46 00 40 00 51 00 30 00 5a 00 42 00 38 00 40 00 51 00 51 00 51 00 51 00 51 00 51 00 30 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_MBCH_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {37 00 58 00 78 00 37 00 66 00 46 00 76 00 56 00 6b 00 66 00 2b 00 35 00 56 00 36 00 38 00 72 00 79 00 5a 00 4a 00 39 00 4a 00 56 00 75 00 57 00 59 00 7a 00 74 00 53 00 6e 00 69 00 69 00 78 00 } //1 7Xx7fFvVkf+5V68ryZJ9JVuWYztSniix
		$a_01_1 = {54 00 69 00 68 00 43 00 2b 00 32 00 57 00 69 00 64 00 31 00 4e 00 35 00 52 00 68 00 4d 00 4f 00 2b 00 55 00 66 00 43 00 63 00 52 00 51 00 39 00 68 00 74 00 47 00 5a 00 46 00 6a 00 54 00 } //1 TihC+2Wid1N5RhMO+UfCcRQ9htGZFjT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}