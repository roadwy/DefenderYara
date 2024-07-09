
rule Trojan_Win32_Qakbot_ED_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 d8 43 8b 45 d8 89 18 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}
rule Trojan_Win32_Qakbot_ED_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 a1 ?? ?? ?? ?? 33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 02 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_ED_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {44 69 73 63 6f 6e 6e 65 63 74 4e 61 6d 65 64 50 69 70 65 } //1 DisconnectNamedPipe
		$a_01_1 = {4f 70 65 6e 53 74 6f 72 61 67 65 } //1 OpenStorage
		$a_01_2 = {6d 6e 6a 68 75 69 76 34 30 } //1 mnjhuiv40
		$a_01_3 = {31 38 32 39 33 } //1 18293
		$a_01_4 = {61 65 72 6f 66 6c 6f 74 } //1 aeroflot
		$a_01_5 = {4a 6a 69 73 63 68 75 67 } //1 Jjischug
		$a_01_6 = {31 2e 32 2e 31 31 } //1 1.2.11
		$a_01_7 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}