
rule Trojan_Win32_Zbot_CR_MTB{
	meta:
		description = "Trojan:Win32/Zbot.CR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 45 01 89 85 90 02 04 8b 8d 90 02 04 8b 95 90 02 04 8d 44 0a 17 89 85 90 02 04 0f b7 4d e4 8b 15 90 02 04 8d 44 0a 44 a3 90 02 04 8b 8d 90 02 04 83 c1 49 83 f1 4c 89 4d ec e9 90 00 } //01 00 
		$a_01_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00 
		$a_01_3 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}