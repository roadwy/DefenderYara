
rule Trojan_Win32_Qakbot_DJ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {6f 75 74 2e 64 6c 6c } //1 out.dll
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_2 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllUnregisterServer
		$a_81_3 = {61 6e 6f 6e 79 6d 6f 75 73 6c 79 } //1 anonymously
		$a_81_4 = {64 65 76 69 74 61 6c 69 7a 61 74 69 6f 6e } //1 devitalization
		$a_81_5 = {69 6e 74 65 72 6c 69 6e 67 75 69 73 74 69 63 } //1 interlinguistic
		$a_81_6 = {70 68 69 6c 61 74 68 6c 65 74 69 63 } //1 philathletic
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}