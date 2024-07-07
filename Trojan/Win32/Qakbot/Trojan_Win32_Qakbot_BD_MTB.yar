
rule Trojan_Win32_Qakbot_BD_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 43 78 8b 83 b0 00 00 00 83 e8 0c 31 43 48 b8 5a 4c 0c 00 2b 83 94 00 00 00 2b 43 2c 01 83 a4 00 00 00 8b 53 48 8b 43 14 81 c2 1b 03 f3 ff 03 93 94 00 00 00 05 0f 98 05 00 0f af 53 64 89 53 64 03 83 10 01 00 00 33 c2 89 43 64 8b 83 a4 00 00 00 05 13 98 05 00 03 83 10 01 00 00 01 43 48 8b 83 a0 00 00 00 35 80 7a 33 34 01 43 48 81 fd c0 65 04 00 0f } //4
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}