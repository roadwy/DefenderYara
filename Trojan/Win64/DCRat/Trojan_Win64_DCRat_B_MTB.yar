
rule Trojan_Win64_DCRat_B_MTB{
	meta:
		description = "Trojan:Win64/DCRat.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d6 85 c0 75 90 01 01 48 83 c3 90 01 01 48 83 c7 90 01 01 48 81 ff 90 01 04 75 90 09 07 00 4a 8b 0c 27 48 89 da 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}