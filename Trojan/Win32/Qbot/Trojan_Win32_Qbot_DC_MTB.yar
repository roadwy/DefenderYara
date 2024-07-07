
rule Trojan_Win32_Qbot_DC_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {6f 75 74 2e 64 6c 6c } //1 out.dll
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_2 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllUnregisterServer
		$a_81_3 = {62 65 6c 65 6d 6e 6f 69 64 65 61 } //1 belemnoidea
		$a_81_4 = {69 73 63 68 69 6f 61 6e 61 6c } //1 ischioanal
		$a_81_5 = {6f 76 65 72 68 6f 6e 65 73 74 6c 79 } //1 overhonestly
		$a_81_6 = {70 65 74 61 6c 6f 64 69 63 } //1 petalodic
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}