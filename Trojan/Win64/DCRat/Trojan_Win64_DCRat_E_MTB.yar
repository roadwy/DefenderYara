
rule Trojan_Win64_DCRat_E_MTB{
	meta:
		description = "Trojan:Win64/DCRat.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {4c 8b 17 4f 0f be 5c 8a 90 01 01 45 0f b6 1c 0b 41 c0 e3 90 01 01 4f 0f be 54 8a 90 01 01 45 0f b6 14 0a 41 80 e2 90 01 01 45 08 da 48 83 7d f8 90 01 01 4d 89 c3 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}