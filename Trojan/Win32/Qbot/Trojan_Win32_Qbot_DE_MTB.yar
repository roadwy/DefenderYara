
rule Trojan_Win32_Qbot_DE_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {6f 75 74 2e 64 6c 6c } //1 out.dll
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_2 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllUnregisterServer
		$a_81_3 = {61 64 64 6c 65 70 61 74 65 64 6e 65 73 73 } //1 addlepatedness
		$a_81_4 = {63 68 6f 6e 64 72 6f 67 65 6e 6f 75 73 } //1 chondrogenous
		$a_81_5 = {6d 65 74 68 79 6c 6e 61 70 68 74 68 61 6c 65 6e 65 } //1 methylnaphthalene
		$a_81_6 = {73 70 6f 6b 65 73 77 6f 6d 61 6e 73 68 69 70 } //1 spokeswomanship
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}