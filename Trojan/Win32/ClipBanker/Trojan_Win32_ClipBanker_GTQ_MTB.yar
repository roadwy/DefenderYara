
rule Trojan_Win32_ClipBanker_GTQ_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.GTQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {89 07 89 5f 04 89 4f 08 89 57 0c 8b 45 e4 8b 4d f0 89 45 f4 81 f1 90 01 04 8b 45 ec 35 90 01 04 89 35 98 e2 42 00 0b c8 8b 45 e8 90 00 } //10
		$a_01_1 = {47 65 74 54 69 6d 65 5a 6f 6e 65 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 GetTimeZoneInformation
		$a_01_2 = {47 65 74 54 6f 6b 65 6e 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 GetTokenInformation
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}