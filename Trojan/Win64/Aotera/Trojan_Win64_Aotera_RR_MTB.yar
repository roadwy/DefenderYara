
rule Trojan_Win64_Aotera_RR_MTB{
	meta:
		description = "Trojan:Win64/Aotera.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8b d1 8b c1 33 44 97 10 44 03 c0 8b d1 41 2b d2 41 c1 c0 11 44 33 c2 41 8b d2 8b c1 41 33 c0 89 44 96 10 41 ff c2 41 83 fa 18 0f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Aotera_RR_MTB_2{
	meta:
		description = "Trojan:Win64/Aotera.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 33 18 45 89 18 45 8b c3 41 c1 e0 0c 41 c1 eb 14 45 0b c3 45 8b c8 44 89 09 44 03 02 44 89 02 48 8b d0 44 33 02 44 89 02 41 8b d0 c1 e2 08 41 c1 e8 18 41 0b d0 44 8b c2 44 89 00 41 03 12 41 89 12 48 8b c1 33 10 89 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}