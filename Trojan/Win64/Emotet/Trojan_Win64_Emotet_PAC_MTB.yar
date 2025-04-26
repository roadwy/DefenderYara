
rule Trojan_Win64_Emotet_PAC_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f af c7 03 d8 8b 44 24 ?? 83 c0 02 0f af c1 2b d8 a1 ?? ?? ?? ?? 8b d0 0f af d0 8b 44 24 ?? 2b da 03 de 2b 1d ?? ?? ?? ?? 8a 0c 2b 30 08 ff 44 24 ?? 8b 44 24 ?? 3b 44 24 ?? 0f 82 } //1
		$a_03_1 = {40 0f af c3 0f af c3 2b c1 8d 44 46 ?? 0f af c7 8d 0c 6a 8a 14 08 8b 44 24 ?? 8a 18 8b 4c 24 ?? 32 da 88 18 8b 44 24 ?? 40 3b c1 89 44 24 ?? 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}