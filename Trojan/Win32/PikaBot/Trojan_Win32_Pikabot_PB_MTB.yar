
rule Trojan_Win32_Pikabot_PB_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_1 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllUnregisterServer
		$a_01_2 = {47 65 74 55 73 65 72 50 72 6f 63 65 73 73 48 6f 73 74 } //2 GetUserProcessHost
		$a_03_3 = {f7 f6 0f b6 54 15 ?? 33 ca 8b 45 ?? 03 45 ?? 88 08 eb ?? 8b 4d ?? 51 e8 } //4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_03_3  & 1)*4) >=6
 
}