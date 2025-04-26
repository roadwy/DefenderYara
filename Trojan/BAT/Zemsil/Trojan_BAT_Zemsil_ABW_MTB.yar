
rule Trojan_BAT_Zemsil_ABW_MTB{
	meta:
		description = "Trojan:BAT/Zemsil.ABW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 65 6c 66 49 6e 6a 65 63 74 6f 72 } //1 SelfInjector
		$a_01_1 = {53 68 65 6c 6c 63 6f 64 65 49 6e 6a 65 63 74 } //1 ShellcodeInject
		$a_01_2 = {52 65 6d 6f 74 65 49 6e 6a 65 63 74 6f 72 } //1 RemoteInjector
		$a_01_3 = {53 70 61 77 6e 49 6e 6a 65 63 74 6f 72 } //1 SpawnInjector
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}