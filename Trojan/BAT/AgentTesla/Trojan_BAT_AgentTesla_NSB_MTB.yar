
rule Trojan_BAT_AgentTesla_NSB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {e2 7f 93 4e ff 7f 5e 59 cf 7f 4e 59 83 52 4e 59 4e 59 cf 7f 7e 4e d3 7f 4e 59 cf 7f 4e 59 77 52 3c 59 3c } //1
		$a_01_1 = {0d 59 8e 7f 3d 4e 8e 7f 0d 59 8e 7f 0d 59 36 52 0d 59 } //1
		$a_01_2 = {cf 7f 54 59 ad 52 7a 59 5f 59 e7 7f a1 4e d9 7f 70 59 d6 7f 84 59 6e 52 61 59 50 59 e2 7f a4 4e f7 7f 3c 59 bd 7f 3c 59 65 52 } //1
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}