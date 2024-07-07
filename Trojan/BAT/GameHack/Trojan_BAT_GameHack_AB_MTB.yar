
rule Trojan_BAT_GameHack_AB_MTB{
	meta:
		description = "Trojan:BAT/GameHack.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 "
		
	strings :
		$a_00_0 = {11 0d 1c 62 13 0e 16 13 0f 38 3e 00 00 00 06 11 0f 18 64 e0 07 11 0e 11 0f 19 58 58 e0 91 1f 18 62 07 11 0e 11 0f 18 58 58 e0 91 1f 10 62 60 07 11 0e 11 0f 17 58 58 e0 91 1e 62 60 07 11 0e 11 0f 58 e0 91 60 9e 11 0f 1a 58 13 0f 11 0f 1f 3d } //10
		$a_81_1 = {49 6e 6a 65 63 74 6f 72 } //3 Injector
		$a_81_2 = {5a 65 75 73 } //3 Zeus
		$a_81_3 = {44 6c 6c 49 6e 6a 65 63 74 6f 72 } //3 DllInjector
		$a_81_4 = {62 49 6e 6a 65 63 74 } //3 bInject
		$a_81_5 = {46 75 72 6b 79 } //3 Furky
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=25
 
}