
rule Trojan_Win64_Bobik_CZP_MTB{
	meta:
		description = "Trojan:Win64/Bobik.CZP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {44 8b d0 eb 90 01 02 c1 e2 04 eb 90 01 03 41 c1 ea 05 eb 90 01 03 41 33 d2 71 90 01 01 69 07 90 01 04 01 2c 45 8b d4 eb 02 03 70 41 8b cc eb 90 01 03 c1 e9 0b eb 90 01 04 83 e1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}