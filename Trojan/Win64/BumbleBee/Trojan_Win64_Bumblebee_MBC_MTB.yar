
rule Trojan_Win64_Bumblebee_MBC_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.MBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 04 11 48 83 c2 90 01 01 41 8b 89 90 01 04 41 8b 81 90 01 04 03 c1 35 90 01 04 41 29 41 90 01 01 41 8b 41 90 01 01 83 e8 90 01 01 41 01 41 90 01 01 41 8b 81 90 01 04 33 c1 35 90 01 04 41 29 81 90 01 04 41 8b 81 90 01 04 41 01 81 90 01 04 41 8b 81 90 01 04 41 29 41 90 01 01 48 81 fa 90 01 04 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}