
rule Backdoor_BAT_Bladabindi_gen_E{
	meta:
		description = "Backdoor:BAT/Bladabindi.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4e 4a 53 65 72 76 65 72 2e 4d 44 49 50 61 72 65 6e 74 31 2e 72 65 73 6f 75 72 63 65 73 } //1 NJServer.MDIParent1.resources
		$a_01_1 = {44 00 65 00 76 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 } //1 Devencryption
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}