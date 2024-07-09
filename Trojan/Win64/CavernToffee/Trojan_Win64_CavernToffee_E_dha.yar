
rule Trojan_Win64_CavernToffee_E_dha{
	meta:
		description = "Trojan:Win64/CavernToffee.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5c 00 44 00 48 8d 55 ?? 66 44 89 75 ?? 48 8d 4d ?? c7 45 ?? 65 00 76 00 c7 45 ?? 69 00 63 00 c7 45 ?? 65 00 5c 00 c7 45 ?? 48 00 74 00 c7 45 ?? 74 00 70 00 c7 45 ?? 5c 00 43 00 c7 45 ?? 6f 00 6d 00 c7 45 ?? 6d 00 75 00 c7 45 ?? 6e 00 69 00 c7 45 ?? 63 00 61 00 c7 45 ?? 74 00 69 00 c7 45 ?? 6f 00 6e 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}