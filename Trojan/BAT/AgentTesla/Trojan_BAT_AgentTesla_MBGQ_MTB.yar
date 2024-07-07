
rule Trojan_BAT_AgentTesla_MBGQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 00 11 47 00 69 00 61 00 79 00 2e 00 43 00 43 00 4d } //1
		$a_01_1 = {44 00 65 00 6c 00 65 00 74 00 65 00 4d 00 43 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_MBGQ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 36 62 32 31 39 64 30 30 2d 66 62 38 61 2d 34 66 39 35 2d 39 35 37 38 2d 61 30 32 62 31 38 35 35 62 32 35 65 } //1 $6b219d00-fb8a-4f95-9578-a02b1855b25e
		$a_01_1 = {51 55 41 4e 4c 59 44 41 49 4c 59 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 QUANLYDAILY.Properties.Resources.resource
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_MBGQ_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0a 2b 19 07 06 08 06 18 5a 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a d2 9c 06 17 58 0a 06 07 8e 69 fe 04 13 05 11 05 2d db 90 00 } //1
		$a_01_1 = {51 4c 54 56 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 QLTV.Properties.Resources.resource
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}