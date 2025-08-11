
rule Trojan_BAT_Taskun_MTE_MTB{
	meta:
		description = "Trojan:BAT/Taskun.MTE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {42 75 74 74 72 65 79 20 46 6f 6f 64 20 26 20 44 72 75 67 } //1 Buttrey Food & Drug
		$a_81_1 = {4d 6f 6e 74 65 72 6f 2e 64 6c 6c } //1 Montero.dll
		$a_81_2 = {50 65 75 67 65 6f 74 20 32 30 36 } //1 Peugeot 206
		$a_81_3 = {46 69 6c 65 20 43 6c 65 72 6b 65 72 } //1 File Clerker
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}