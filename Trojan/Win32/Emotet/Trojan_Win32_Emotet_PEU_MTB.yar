
rule Trojan_Win32_Emotet_PEU_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PEU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f b6 54 3c ?? 0f b6 c0 03 c2 99 f7 fb 8a 1c 2e 8a 44 14 ?? 32 c3 88 06 } //1
		$a_02_1 = {8a 14 31 8b 44 24 ?? 32 94 04 ?? ?? ?? ?? 8d 4c 24 ?? 88 16 c7 84 24 ?? ?? ?? ?? ff ff ff ff 90 09 08 00 8b 4c 24 ?? 8b 74 24 } //1
		$a_81_2 = {36 74 6d 2a 50 51 74 54 50 38 6b 31 6e 47 33 6b 6d 73 3f 4d 34 7b 77 46 55 75 77 25 79 7c 39 37 44 34 70 67 47 4e 77 6c 36 33 40 51 57 77 42 72 4f 7c 69 78 34 78 42 69 54 31 24 72 24 72 4f 48 53 } //1 6tm*PQtTP8k1nG3kms?M4{wFUuw%y|97D4pgGNwl63@QWwBrO|ix4xBiT1$r$rOHS
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}