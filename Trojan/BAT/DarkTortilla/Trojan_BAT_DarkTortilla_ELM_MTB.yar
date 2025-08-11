
rule Trojan_BAT_DarkTortilla_ELM_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ELM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_81_0 = {49 6e 6a 65 63 74 69 6f 6e 48 6f 73 74 49 6e 64 65 78 } //2 InjectionHostIndex
		$a_81_1 = {67 65 74 5f 41 6e 74 69 53 61 6e 64 42 6f 78 69 65 } //1 get_AntiSandBoxie
		$a_81_2 = {67 65 74 5f 41 6e 74 69 56 4d } //1 get_AntiVM
		$a_81_3 = {67 65 74 5f 53 74 61 72 74 75 70 50 65 72 73 69 73 74 65 6e 63 65 } //1 get_StartupPersistence
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}