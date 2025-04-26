
rule Trojan_BAT_AgentTesla_EL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 "
		
	strings :
		$a_81_0 = {24 34 62 32 61 64 64 61 64 2d 66 38 65 37 2d 34 65 37 35 2d 62 32 36 35 2d 65 64 39 38 30 39 35 39 39 30 62 66 } //20 $4b2addad-f8e7-4e75-b265-ed98095990bf
		$a_81_1 = {4d 61 74 72 69 78 5f 47 72 61 70 68 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //20 Matrix_Graph.Properties.Resources
		$a_81_2 = {4d 61 74 72 69 78 5f 47 72 61 70 68 2e 47 72 61 70 68 46 6f 72 6d } //1 Matrix_Graph.GraphForm
		$a_81_3 = {64 61 74 61 2f 47 61 75 73 73 2e 74 78 74 } //1 data/Gauss.txt
		$a_81_4 = {64 61 74 61 2f 41 6c 67 6f 50 61 72 61 6d 2e 74 78 74 } //1 data/AlgoParam.txt
		$a_81_5 = {41 63 74 69 76 65 4d 61 72 6b 65 72 } //1 ActiveMarker
		$a_81_6 = {43 72 65 61 74 65 4e 65 77 4d 61 72 6b 65 72 } //1 CreateNewMarker
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=25
 
}
rule Trojan_BAT_AgentTesla_EL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {70 03 11 04 18 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 04 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6a 61 b7 28 ?? ?? ?? 0a 13 07 12 07 28 ?? ?? ?? 0a 13 05 08 11 05 6f ?? ?? ?? 0a 26 07 04 6f ?? ?? ?? 0a 17 da 33 03 } //10
		$a_03_1 = {70 03 11 04 18 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 04 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6a 61 b7 28 ?? ?? ?? 0a 13 06 12 06 28 ?? ?? ?? 0a 13 05 08 11 05 6f ?? ?? ?? 0a 26 07 04 6f ?? ?? ?? 0a 17 da 33 03 } //10
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=12
 
}