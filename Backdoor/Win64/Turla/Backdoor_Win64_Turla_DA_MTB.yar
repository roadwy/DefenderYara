
rule Backdoor_Win64_Turla_DA_MTB{
	meta:
		description = "Backdoor:Win64/Turla.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {57 68 79 20 74 68 65 20 66 2a 63 6b 20 6e 6f 74 3f 3f 3f } //1 Why the f*ck not???
		$a_81_1 = {41 6c 65 72 74 65 72 } //1 Alerter
		$a_81_2 = {73 61 63 72 69 6c 2e 64 6c 6c } //1 sacril.dll
		$a_81_3 = {65 73 74 64 6c 61 77 66 2e 66 65 73 } //1 estdlawf.fes
		$a_81_4 = {49 66 20 74 68 65 20 73 65 72 76 69 63 65 20 69 73 20 73 74 6f 70 70 65 64 2c 20 70 72 6f 67 72 61 6d 73 20 74 68 61 74 20 75 73 65 20 61 64 6d 69 6e 69 73 74 72 61 74 69 76 65 20 61 6c 65 72 74 73 20 77 69 6c 6c 20 6e 6f 74 20 72 65 63 65 69 76 65 20 74 68 65 6d 2e } //1 If the service is stopped, programs that use administrative alerts will not receive them.
		$a_81_5 = {49 66 20 74 68 69 73 20 73 65 72 76 69 63 65 20 69 73 20 64 69 73 61 62 6c 65 64 2c 20 61 6e 79 20 73 65 72 76 69 63 65 73 20 74 68 61 74 20 65 78 70 6c 69 63 69 74 6c 79 20 64 65 70 65 6e 64 20 6f 6e 20 69 74 20 77 69 6c 6c 20 66 61 69 6c 20 74 6f 20 73 74 61 72 74 2e } //1 If this service is disabled, any services that explicitly depend on it will fail to start.
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=5
 
}