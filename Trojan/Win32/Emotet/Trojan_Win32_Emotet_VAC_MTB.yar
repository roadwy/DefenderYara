
rule Trojan_Win32_Emotet_VAC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.VAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d8 21 f0 8b 74 24 18 8a 0c 06 8b 44 24 20 8a 2c 38 30 e9 8b 5c 24 1c 88 0c 3b 8b 44 24 14 8d bc 07 97 57 aa d9 c7 44 24 ?? ff ff ff ff c7 44 24 ?? c8 c8 af e4 8b 44 24 0c 89 44 24 34 89 7c 24 38 8b 44 24 04 89 44 24 3c 8b 44 24 30 39 c7 74 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}