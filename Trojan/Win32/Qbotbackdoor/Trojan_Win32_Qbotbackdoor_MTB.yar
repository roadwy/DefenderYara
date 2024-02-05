
rule Trojan_Win32_Qbotbackdoor_MTB{
	meta:
		description = "Trojan:Win32/Qbotbackdoor!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 45 e0 8b 4d e8 8a 14 01 8b 75 e4 88 14 06 69 7d f0 90 01 04 89 7d f0 83 c0 01 8b 7d ec 39 f8 89 45 e0 75 90 00 } //01 00 
		$a_00_1 = {61 73 73 68 6f 6c 65 74 72 61 63 6b 69 6e 67 78 61 76 69 65 72 51 32 30 31 30 2e 39 34 77 74 68 65 62 65 } //01 00 
		$a_00_2 = {6a 59 65 73 68 61 73 32 } //01 00 
		$a_00_3 = {74 68 65 76 79 31 31 32 32 33 33 } //00 00 
	condition:
		any of ($a_*)
 
}