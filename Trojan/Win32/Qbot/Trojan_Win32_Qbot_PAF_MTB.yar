
rule Trojan_Win32_Qbot_PAF_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b d8 8b 45 d8 89 18 8b 45 c4 03 45 a4 89 45 a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_PAF_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.PAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c2 89 45 f0 0f b6 0d ?? ?? ?? ?? 33 4d f0 89 4d f0 0f b6 15 ?? ?? ?? ?? 33 55 f0 89 55 f0 0f b6 05 ?? ?? ?? ?? 33 45 f0 89 45 f0 0f b6 0d ?? ?? ?? ?? 8b 55 f0 2b d1 89 55 f0 0f b6 05 ?? ?? ?? ?? 33 45 f0 89 45 f0 8b 0d ?? ?? ?? ?? 03 4d ec 8a 55 f0 88 11 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_PAF_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.PAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 } //1 SOFTWAREMicrosoft
		$a_01_1 = {52 66 45 55 76 76 4c 43 66 45 6a 6a 71 66 78 42 6b 4f 65 54 6e 48 61 4d 56 57 49 43 7a 57 70 48 49 76 67 73 46 4e 4e } //1 RfEUvvLCfEjjqfxBkOeTnHaMVWICzWpHIvgsFNN
		$a_01_2 = {49 75 63 4e 72 67 68 6d 48 47 53 7a 62 49 66 66 79 71 64 59 64 52 79 51 46 66 5a 6c 51 69 67 65 4a 52 65 41 } //1 IucNrghmHGSzbIffyqdYdRyQFfZlQigeJReA
		$a_01_3 = {59 4f 70 4d 73 73 63 44 50 54 41 69 66 55 4a 49 47 71 43 41 43 62 44 44 66 5a 71 75 73 65 66 76 50 65 65 } //1 YOpMsscDPTAifUJIGqCACbDDfZqusefvPee
		$a_01_4 = {61 7a 69 65 74 68 61 6e 65 } //1 aziethane
		$a_01_5 = {62 69 67 68 65 61 72 74 65 64 6e 65 73 73 } //1 bigheartedness
		$a_01_6 = {77 6f 6e 6e 69 6e 67 } //1 wonning
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}