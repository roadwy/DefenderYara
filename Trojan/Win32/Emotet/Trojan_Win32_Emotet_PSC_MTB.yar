
rule Trojan_Win32_Emotet_PSC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 44 04 ?? 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 44 24 ?? 8a 4c 14 ?? 30 08 } //1
		$a_81_1 = {68 57 73 4a 4c 71 6d 42 39 4d 31 61 5a 73 64 69 6b 79 50 46 34 31 37 48 56 75 64 4a 45 75 63 35 67 31 } //1 hWsJLqmB9M1aZsdikyPF417HVudJEuc5g1
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}