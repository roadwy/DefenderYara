
rule Trojan_BAT_AgentTesla_NUT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NUT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {40 01 57 55 a2 cb 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 a8 00 00 00 18 00 00 00 94 00 00 00 3c 01 00 00 d0 00 00 00 3e 01 00 00 45 02 00 00 01 } //1
		$a_01_1 = {24 35 65 38 65 61 64 36 62 2d 31 63 38 63 2d 34 64 37 63 2d 62 64 31 66 2d 32 35 33 62 66 30 39 33 33 38 38 39 } //1 $5e8ead6b-1c8c-4d7c-bd1f-253bf0933889
		$a_01_2 = {4d 00 55 00 4c 00 54 00 49 00 4a 00 55 00 47 00 41 00 44 00 4f 00 52 00 } //1 MULTIJUGADOR
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}