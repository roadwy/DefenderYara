
rule Trojan_Win64_Dridex_EM_MTB{
	meta:
		description = "Trojan:Win64/Dridex.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 34 89 ca 83 e2 1f 41 89 c8 45 89 c1 89 d2 41 89 d2 4c 8b 5c 24 18 43 8a 1c 0b 42 2a 1c 10 48 8b 44 24 08 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Dridex_EM_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {4d 6b d0 28 49 89 c3 4d 01 d3 49 83 c3 1c 4d 6b d0 28 48 89 c6 4c 01 d6 48 83 c6 20 4d 6b d0 28 4c 01 d0 89 cf 41 89 fa 4c 03 94 24 b8 00 00 00 45 00 c9 41 8b 3b 48 8b 16 33 38 } //00 00 
	condition:
		any of ($a_*)
 
}