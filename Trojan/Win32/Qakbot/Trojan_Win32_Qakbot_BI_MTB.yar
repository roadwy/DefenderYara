
rule Trojan_Win32_Qakbot_BI_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4d e6 8b 55 08 03 55 e0 0f b6 02 33 c1 8b 4d 08 03 4d e0 88 01 8d 55 e8 52 8d 4d e8 } //2
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_2 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllUnregisterServer
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}