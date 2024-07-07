
rule Trojan_Win32_Qbot_DD_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {6f 75 74 2e 64 6c 6c } //1 out.dll
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_2 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllUnregisterServer
		$a_81_3 = {70 79 6c 65 74 68 72 6f 6d 62 6f 70 68 6c 65 62 69 74 69 73 } //1 pylethrombophlebitis
		$a_81_4 = {62 61 63 74 65 72 69 63 69 64 65 } //1 bactericide
		$a_81_5 = {64 65 6c 69 63 61 74 65 73 73 65 } //1 delicatesse
		$a_81_6 = {74 6f 73 73 69 63 61 74 65 64 } //1 tossicated
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}