
rule Trojan_Win64_Emotet_PAC_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f af c7 03 d8 8b 44 24 90 01 01 83 c0 02 0f af c1 2b d8 a1 90 01 04 8b d0 0f af d0 8b 44 24 90 01 01 2b da 03 de 2b 1d 90 01 04 8a 0c 2b 30 08 ff 44 24 90 01 01 8b 44 24 90 01 01 3b 44 24 90 01 01 0f 82 90 00 } //01 00 
		$a_03_1 = {40 0f af c3 0f af c3 2b c1 8d 44 46 90 01 01 0f af c7 8d 0c 6a 8a 14 08 8b 44 24 90 01 01 8a 18 8b 4c 24 90 01 01 32 da 88 18 8b 44 24 90 01 01 40 3b c1 89 44 24 90 01 01 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}