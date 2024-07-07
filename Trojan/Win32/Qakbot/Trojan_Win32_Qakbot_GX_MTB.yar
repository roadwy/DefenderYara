
rule Trojan_Win32_Qakbot_GX_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 63 72 68 61 30 32 34 61 79 36 38 2e 64 6c 6c } //1 pcrha024ay68.dll
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_2 = {6f 77 6e 65 72 20 64 65 61 64 } //1 owner dead
		$a_01_3 = {43 6f 6e 6e 65 63 74 4e 61 6d 65 64 50 69 70 65 } //1 ConnectNamedPipe
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}