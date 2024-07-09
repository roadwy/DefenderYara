
rule Trojan_Win32_Emotet_RW_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 04 0f af 05 ?? ?? ?? ?? 03 d0 8d 47 ?? 0f af c7 2b d0 8b 44 24 ?? 2b d3 2b d1 8a 0c 32 30 08 8b 44 24 ?? 40 89 44 24 ?? 3b 44 24 ?? 0f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_RW_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {5f 23 69 40 59 52 21 49 5f 70 44 31 56 50 52 5a 33 79 69 24 50 54 3c 34 79 24 69 49 23 79 39 23 74 38 29 58 41 34 50 39 } //_#i@YR!I_pD1VPRZ3yi$PT<4y$iI#y9#t8)XA4P9  1
		$a_03_1 = {83 c4 04 f7 d8 50 ff 15 ?? ?? ?? ?? 89 45 ?? eb ?? 6a 40 68 00 30 00 00 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_RW_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {5e 35 23 43 61 73 56 30 24 34 26 4e 47 62 45 54 4b 53 24 35 3f 33 51 35 45 49 4a 42 78 74 75 67 6b 35 6a 48 79 53 53 53 67 31 63 45 38 39 74 61 3c 4b 78 51 71 70 32 6b 50 4b 72 46 71 32 56 56 7a 6c 41 24 64 79 32 77 67 77 39 7a 75 32 78 62 3c 26 6a 4a } //^5#CasV0$4&NGbETKS$5?3Q5EIJBxtugk5jHySSSg1cE89ta<KxQqp2kPKrFq2VVzlA$dy2wgw9zu2xb<&jJ  1
		$a_03_1 = {0b e9 55 57 6a 00 6a ff ff 15 ?? ?? ?? ?? e9 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}