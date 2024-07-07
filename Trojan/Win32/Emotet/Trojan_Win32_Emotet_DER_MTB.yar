
rule Trojan_Win32_Emotet_DER_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 e5 08 00 00 f7 f9 8b 4c 24 90 01 01 8b 84 24 90 01 04 8a 54 14 90 01 01 30 14 01 90 00 } //1
		$a_81_1 = {50 41 79 70 62 4d 4a 68 71 48 54 32 37 72 72 50 56 55 48 56 6b 75 4c 7a 78 63 52 32 68 48 48 7a 64 6e 74 34 58 4a 70 57 45 48 } //1 PAypbMJhqHT27rrPVUHVkuLzxcR2hHHzdnt4XJpWEH
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_DER_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.DER!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 6c 24 44 8b c7 2b c1 2b c6 03 54 24 40 8d 04 82 8b 54 24 4c 03 c3 8a 04 10 30 45 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}