
rule Trojan_Win32_Qbot_EN_MTB{
	meta:
		description = "Trojan:Win32/Qbot.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {6f 75 74 2e 64 6c 6c } //1 out.dll
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_2 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllUnregisterServer
		$a_81_3 = {4b 4a 49 34 34 31 41 30 61 56 42 41 79 4c 6b 61 39 32 50 } //1 KJI441A0aVBAyLka92P
		$a_81_4 = {45 63 54 47 33 4e 54 43 69 77 69 31 66 54 47 4b 36 48 34 } //1 EcTG3NTCiwi1fTGK6H4
		$a_81_5 = {49 6d 54 6f 62 49 4f 62 39 4c 36 4a 72 71 43 46 45 4e } //1 ImTobIOb9L6JrqCFEN
		$a_81_6 = {59 70 76 4a 6f 6d 33 6a 6d 75 39 30 64 48 42 57 71 } //1 YpvJom3jmu90dHBWq
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}