
rule Trojan_BAT_AsyncRat_SGB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.SGB!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 42 6f 74 4b 69 6c 6c 65 72 } //1 RunBotKiller
		$a_01_1 = {53 68 65 6c 6c 57 72 69 74 65 4c 69 6e 65 } //1 ShellWriteLine
		$a_01_2 = {53 65 74 48 6f 6f 6b } //1 SetHook
		$a_01_3 = {69 6e 6a 65 63 74 69 6f 6e } //1 injection
		$a_01_4 = {53 74 75 62 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //2 Stub.g.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=5
 
}