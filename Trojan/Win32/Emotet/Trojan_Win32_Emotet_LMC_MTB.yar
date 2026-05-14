
rule Trojan_Win32_Emotet_LMC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.LMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 84 24 94 02 00 00 ff ff ff ff c7 84 24 90 02 00 00 d1 d6 a4 b0 8b 84 24 88 02 00 00 8b 8c 24 8c 02 00 00 35 0a a7 d8 13 8d 54 24 68 89 54 24 64 f2 0f 10 44 24 78 } //20
		$a_01_1 = {8b 54 24 58 69 f2 7c 11 ea 32 89 b4 24 9c 02 00 00 83 c1 04 89 8c 24 80 02 00 00 8b 4c 24 70 8b 74 24 74 81 e9 a8 35 2c 0c } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}