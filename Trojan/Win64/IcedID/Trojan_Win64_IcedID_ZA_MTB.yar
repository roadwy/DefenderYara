
rule Trojan_Win64_IcedID_ZA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e2 90 01 01 2b c2 41 90 01 03 41 90 01 02 41 90 01 03 03 c8 48 90 01 04 03 cb ff c3 48 90 01 02 42 90 01 08 41 90 01 04 41 90 01 04 3b 5c 24 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}