
rule Trojan_Win64_Emotet_F_MTB{
	meta:
		description = "Trojan:Win64/Emotet.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 54 24 74 89 44 24 50 4c 8b 84 24 80 00 00 00 4d 89 c1 49 d3 e9 4c 89 8c 24 80 00 00 00 } //02 00 
		$a_01_1 = {48 8b 4c 24 48 48 8b 54 24 48 48 d3 e2 48 89 94 24 80 00 00 00 c7 44 24 54 01 00 00 00 89 44 24 40 8b 44 24 54 } //00 00 
	condition:
		any of ($a_*)
 
}