
rule Trojan_Win32_Zbot_CA_MTB{
	meta:
		description = "Trojan:Win32/Zbot.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 83 c0 01 89 45 f4 8b 4d f4 3b 4d 10 7d 1f 8b 55 f4 89 55 fc 8b 45 0c 03 45 fc 0f b6 08 89 4d f0 8b 55 08 03 55 f4 8a 45 f0 88 02 eb d0 } //1
		$a_03_1 = {23 d0 81 ea 90 02 04 89 55 90 00 } //1
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_4 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //1 GetTickCount
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}