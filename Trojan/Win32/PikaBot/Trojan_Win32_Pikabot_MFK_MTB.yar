
rule Trojan_Win32_Pikabot_MFK_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.MFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 4d e4 0f b6 89 ?? ?? ?? ?? 8b 45 e4 33 d2 be 1a 00 00 00 f7 f6 0f b6 54 15 b4 33 ca 8b 45 f0 03 45 e4 88 08 eb } //1
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_2 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllUnregisterServer
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}