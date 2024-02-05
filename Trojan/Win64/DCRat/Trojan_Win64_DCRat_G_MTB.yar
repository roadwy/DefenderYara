
rule Trojan_Win64_DCRat_G_MTB{
	meta:
		description = "Trojan:Win64/DCRat.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 00 0f be c0 48 98 48 8d 15 90 01 04 0f b6 04 10 0f be c0 c1 e0 02 83 e0 90 01 01 89 c6 48 8b 45 e8 48 c1 e0 02 48 83 c0 01 48 89 c2 48 8b 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}