
rule Trojan_BAT_AgentTesla_AYA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_01_0 = {24 34 61 32 66 38 66 62 36 2d 31 30 37 37 2d 34 36 39 61 2d 39 32 34 36 2d 37 33 36 65 36 61 66 65 38 64 61 31 } //2 $4a2f8fb6-1077-469a-9246-736e6afe8da1
		$a_01_1 = {41 64 64 52 6f 6f 74 6b 69 74 } //2 AddRootkit
		$a_01_2 = {69 73 56 4d 5f 62 79 5f 77 69 6d 5f 74 65 6d 70 65 72 } //1 isVM_by_wim_temper
		$a_01_3 = {43 6c 69 65 6e 74 2e 48 65 6c 70 65 72 } //1 Client.Helper
		$a_01_4 = {45 6e 76 69 72 6f 6e 6d 65 6e 74 44 65 74 65 63 74 65 64 } //1 EnvironmentDetected
		$a_01_5 = {52 75 6e 41 6e 74 69 41 6e 61 6c 79 73 69 73 } //1 RunAntiAnalysis
		$a_01_6 = {52 65 6d 6f 76 65 46 69 6c 65 53 65 63 75 72 69 74 79 } //1 RemoveFileSecurity
		$a_01_7 = {44 65 63 6f 64 45 6e 63 6f 64 } //1 DecodEncod
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=10
 
}