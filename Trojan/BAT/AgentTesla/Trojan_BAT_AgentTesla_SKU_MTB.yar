
rule Trojan_BAT_AgentTesla_SKU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {48 61 72 6d 6f 6e 69 7a 65 67 72 61 63 65 66 75 6c } //1 Harmonizegraceful
		$a_81_1 = {4d 65 73 4d 65 72 69 7a 69 6e 67 67 6c 65 65 66 75 6c } //1 MesMerizinggleeful
		$a_81_2 = {4e 69 67 68 74 6d 61 72 65 77 68 69 6d 73 79 } //1 Nightmarewhimsy
		$a_81_3 = {64 58 52 58 75 42 58 63 6b 68 56 6f 51 4a 4c 56 } //1 dXRXuBXckhVoQJLV
		$a_81_4 = {24 38 62 38 61 61 62 30 66 2d 64 63 39 62 2d 34 63 39 30 2d 38 31 35 64 2d 37 34 38 62 39 31 66 32 62 36 34 34 } //1 $8b8aab0f-dc9b-4c90-815d-748b91f2b644
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_SKU_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {4f 70 65 6e 4d 63 64 66 2e 53 74 72 75 63 74 73 } //1 OpenMcdf.Structs
		$a_81_1 = {4c 7a 65 66 67 74 64 79 64 6f 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Lzefgtdydo.Properties.Resources.resources
		$a_81_2 = {24 35 61 63 61 32 61 63 32 2d 32 37 38 61 2d 34 38 66 32 2d 62 36 39 31 2d 66 36 31 37 63 64 32 36 39 61 32 33 } //1 $5aca2ac2-278a-48f2-b691-f617cd269a23
		$a_81_3 = {74 77 6f 50 6e 70 68 75 2e 43 6f 6e 73 75 6d 65 72 73 } //1 twoPnphu.Consumers
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}