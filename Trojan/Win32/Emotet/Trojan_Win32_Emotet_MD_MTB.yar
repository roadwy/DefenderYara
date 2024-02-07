
rule Trojan_Win32_Emotet_MD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {65 2a 4a 71 41 6a 41 4c 6d 31 38 6c 41 40 55 40 37 5e 5a 41 56 37 46 34 2a 6a } //01 00  e*JqAjALm18lA@U@7^ZAV7F4*j
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_2 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 4b 61 73 6c } //01 00  DllUnregisterServerKasl
		$a_01_3 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //01 00  LockResource
		$a_01_4 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //00 00  UnhookWindowsHookEx
	condition:
		any of ($a_*)
 
}