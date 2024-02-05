
rule Trojan_Win64_DCRat_C_MTB{
	meta:
		description = "Trojan:Win64/DCRat.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {4c 89 e2 49 89 d8 ff 90 01 01 3d 90 01 04 74 90 01 01 48 83 c3 90 01 01 48 83 c6 90 01 01 48 81 fe 90 01 04 75 90 09 04 00 4a 8b 0c 3e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}