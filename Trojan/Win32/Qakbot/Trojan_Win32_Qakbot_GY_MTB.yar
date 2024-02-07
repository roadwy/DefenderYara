
rule Trojan_Win32_Qakbot_GY_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {56 83 e6 00 0b b3 90 01 04 83 e1 00 31 f1 5e fc f3 a4 52 c7 04 e4 ff ff 0f 00 59 83 bb 90 01 04 00 75 90 00 } //0a 00 
		$a_02_1 = {83 c4 04 81 e0 00 00 00 00 8f 45 f8 33 45 f8 8f 83 90 01 04 21 8b 90 01 04 01 83 90 01 04 83 bb 90 01 04 00 75 90 01 01 ff 93 90 01 04 50 8f 45 fc ff 75 fc 8f 83 90 01 04 ff a3 90 01 04 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GY_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 64 66 6e 62 64 66 6e 64 6e 64 64 6e 64 66 64 62 64 66 } //01 00  ddfnbdfndnddndfdbdf
		$a_01_1 = {73 64 66 73 64 66 73 64 } //01 00  sdfsdfsd
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_3 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllUnregisterServer
		$a_01_4 = {70 69 6e 6e 69 67 72 61 64 61 } //01 00  pinnigrada
		$a_01_5 = {73 6f 70 68 6f 6d 6f 72 69 63 61 6c 6c 79 } //01 00  sophomorically
		$a_01_6 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00  IsDebuggerPresent
	condition:
		any of ($a_*)
 
}