
rule Trojan_BAT_AgentTesla_JTI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JTI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {24 62 64 66 38 39 34 62 61 2d 61 31 63 32 2d 34 39 32 64 2d 38 39 38 66 2d 66 63 62 64 33 62 39 63 38 34 32 65 } //1 $bdf894ba-a1c2-492d-898f-fcbd3b9c842e
		$a_81_1 = {44 31 32 33 31 33 31 35 37 36 35 } //1 D1231315765
		$a_81_2 = {46 35 33 34 35 33 34 35 33 35 34 33 35 } //1 F534534535435
		$a_81_3 = {44 32 33 31 33 31 32 35 34 33 35 } //1 D2313125435
		$a_81_4 = {44 32 38 38 33 32 31 32 33 38 37 32 31 33 32 31 } //1 D288321238721321
		$a_81_5 = {44 36 35 34 39 36 34 35 31 32 33 } //1 D6549645123
		$a_81_6 = {44 38 36 35 36 35 33 34 } //1 D8656534
		$a_81_7 = {47 65 6e 65 72 61 74 69 6f 6e } //1 Generation
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}