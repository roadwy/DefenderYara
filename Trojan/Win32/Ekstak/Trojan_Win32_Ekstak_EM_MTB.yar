
rule Trojan_Win32_Ekstak_EM_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 8b 75 14 56 e8 ?? ?? ?? ?? 68 38 9c 65 00 c7 05 38 9c 65 00 44 00 00 00 ff 15 ?? ?? ?? ?? e9 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}
rule Trojan_Win32_Ekstak_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2a 01 00 00 00 81 7c 8b 00 a3 e0 87 00 00 be 0a 00 d4 bd 14 99 22 a4 87 00 00 d4 00 00 52 85 42 1a } //5
		$a_01_1 = {2a 01 00 00 00 a3 18 88 00 c5 7c 84 00 00 be 0a 00 d4 bd 14 99 66 40 84 00 00 d4 00 00 76 d1 33 f7 } //5
		$a_01_2 = {2a 01 00 00 00 e9 56 87 00 0b bb 83 00 00 be 0a 00 d4 bd 14 99 91 7e 83 00 00 d4 00 00 b0 06 f5 c5 } //5
		$a_01_3 = {53 00 70 00 6c 00 69 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 56 00 42 00 } //1 SplitControlVB
		$a_01_4 = {56 00 42 00 4d 00 61 00 69 00 6c 00 41 00 67 00 65 00 6e 00 74 00 } //1 VBMailAgent
		$a_01_5 = {56 00 42 00 53 00 63 00 72 00 6f 00 6c 00 6c 00 4c 00 49 00 42 00 } //1 VBScrollLIB
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}