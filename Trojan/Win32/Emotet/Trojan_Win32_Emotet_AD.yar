
rule Trojan_Win32_Emotet_AD{
	meta:
		description = "Trojan:Win32/Emotet.AD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 65 78 70 6c 6f 69 74 73 77 61 73 4f 53 4a 74 6f 54 68 65 } //1 pexploitswasOSJtoThe
		$a_01_1 = {74 68 65 70 72 65 76 69 6f 75 73 6c 79 6d 65 6d 6f 72 79 57 65 62 4b 69 74 43 68 72 6f 6d 65 59 } //1 thepreviouslymemoryWebKitChromeY
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_AD_2{
	meta:
		description = "Trojan:Win32/Emotet.AD,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ff 8b ca a3 ?? ?? ?? ?? 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 31 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 8b ff 01 05 ?? ?? ?? ?? 8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 5f 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_AD_3{
	meta:
		description = "Trojan:Win32/Emotet.AD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 11 2a 44 24 4b 8a 64 24 2b 30 c4 00 e2 8b 4c 24 0c 8b 74 24 14 88 14 31 } //1
		$a_01_1 = {8a 75 cb 80 c6 73 8b 45 e4 8b 4d cc 02 34 08 28 d6 8b 75 e0 88 34 0e 83 c1 3e 8b 7d e8 39 f9 8b 5d c4 89 5d d0 89 4d d4 72 ae } //1
		$a_03_2 = {8b 45 e4 8b 4d f4 81 c1 7a 04 8e b7 89 c2 21 ca 8b 4d e8 89 0c 24 8b 75 ec 89 74 24 04 89 44 24 08 0f b6 14 15 ?? ?? ?? ?? 89 54 24 0c 89 45 e0 e8 d2 0b 00 00 8b 45 e0 83 c0 01 8b 4d f0 39 c8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}