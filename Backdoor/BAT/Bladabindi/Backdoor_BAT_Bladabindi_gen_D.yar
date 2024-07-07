
rule Backdoor_BAT_Bladabindi_gen_D{
	meta:
		description = "Backdoor:BAT/Bladabindi.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4e 4a 53 65 72 76 65 72 } //1 NJServer
		$a_01_1 = {52 53 4d 44 65 63 72 79 70 74 } //1 RSMDecrypt
		$a_01_2 = {4e 00 4a 00 43 00 72 00 79 00 70 00 74 00 65 00 } //1 NJCrypte
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}