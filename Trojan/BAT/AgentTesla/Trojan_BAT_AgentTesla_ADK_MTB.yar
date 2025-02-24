
rule Trojan_BAT_AgentTesla_ADK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 19 8d 5b 00 00 01 25 16 12 02 28 72 00 00 0a 9c 25 17 12 02 28 73 00 00 0a 9c 25 18 12 02 28 74 00 00 0a 9c } //2
		$a_01_1 = {52 65 73 75 6d 65 73 41 70 70 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 ResumesApp.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_BAT_AgentTesla_ADK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {30 41 33 42 43 44 32 38 31 31 30 43 31 30 44 41 39 32 34 37 38 33 38 46 34 45 44 34 41 30 37 39 44 30 43 39 37 44 43 46 35 39 46 30 43 43 45 45 44 31 30 37 32 31 45 32 33 37 45 45 44 34 38 34 } //1 0A3BCD28110C10DA9247838F4ED4A079D0C97DCF59F0CCEED10721E237EED484
		$a_01_1 = {45 50 31 5f 52 65 73 74 61 75 72 61 6e 74 65 2e 50 72 6f 70 65 72 74 69 65 73 } //1 EP1_Restaurante.Properties
		$a_01_2 = {24 34 33 61 33 62 32 32 62 2d 66 35 35 38 2d 34 38 39 61 2d 62 61 32 31 2d 37 32 65 35 35 63 64 36 66 62 39 39 } //1 $43a3b22b-f558-489a-ba21-72e55cd6fb99
		$a_01_3 = {34 38 35 46 34 48 38 34 47 48 35 47 34 32 43 42 53 37 48 35 39 34 78 } //1 485F4H84GH5G42CBS7H594x
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}