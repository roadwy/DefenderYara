
rule Trojan_BAT_Zema_A_MTB{
	meta:
		description = "Trojan:BAT/Zema.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_81_0 = {66 64 73 66 64 73 2e 65 78 65 } //5 fdsfds.exe
		$a_81_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //5 VirtualProtect
		$a_81_2 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //5 ToBase64String
		$a_81_3 = {42 6c 6f 63 6b 43 6f 70 79 } //5 BlockCopy
		$a_01_4 = {76 00 66 00 64 00 76 00 64 00 66 00 64 00 76 00 66 00 76 00 64 00 66 00 } //1 vfdvdfdvfvdf
		$a_01_5 = {74 00 6e 00 64 00 66 00 67 00 62 00 66 00 } //1 tndfgbf
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=21
 
}