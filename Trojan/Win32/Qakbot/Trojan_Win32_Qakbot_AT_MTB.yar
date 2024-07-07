
rule Trojan_Win32_Qakbot_AT_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {30 31 39 37 66 32 61 64 64 64 34 38 32 66 37 30 } //1 0197f2addd482f70
		$a_01_1 = {38 37 30 65 65 38 32 66 63 62 39 30 30 32 62 66 } //1 870ee82fcb9002bf
		$a_01_2 = {37 63 65 31 32 64 38 61 31 30 66 34 63 34 39 62 } //1 7ce12d8a10f4c49b
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Qakbot_AT_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 07 0f b7 44 41 50 31 44 24 68 8b 44 24 10 8b 4c 24 44 41 89 4c 24 44 0f b6 80 82 0b 00 00 3b c8 0f 85 } //4
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}