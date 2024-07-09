
rule Trojan_Win32_Emotet_DFT_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 10 88 16 88 18 0f b6 06 0f b6 d3 03 c2 99 8b f1 f7 fe 8b 45 ?? 8a 54 15 ?? 30 10 } //1
		$a_81_1 = {4a 58 4c 67 38 47 35 35 77 44 6e 63 56 41 69 49 57 65 6c 68 34 33 6e 52 6f 33 38 79 35 6d 65 48 4e 34 43 } //1 JXLg8G55wDncVAiIWelh43nRo38y5meHN4C
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}