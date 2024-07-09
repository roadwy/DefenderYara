
rule Trojan_Win32_Qakbot_QBT_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.QBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 ea 01 d1 81 c1 ?? ?? ?? ?? 89 4f 58 8b 4c 24 24 0f af 01 89 c1 c1 e9 10 8b 57 6c 8b af ?? ?? ?? ?? 8d 72 01 89 77 6c 88 4c 15 00 8b 4f 2c 8d 91 ?? ?? ?? ?? 8b b7 ?? ?? ?? ?? bd ?? ?? ?? ?? 29 cd } //1
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}