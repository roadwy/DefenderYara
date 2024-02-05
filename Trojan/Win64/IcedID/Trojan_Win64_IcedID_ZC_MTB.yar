
rule Trojan_Win64_IcedID_ZC_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 08 48 8b 90 01 02 48 90 01 02 3a db 74 90 01 01 48 90 01 03 48 90 01 04 48 90 01 02 66 90 01 02 74 90 00 } //01 00 
		$a_03_1 = {33 c8 8b c1 e9 90 01 04 33 d2 48 90 01 02 b9 90 01 04 3a c0 74 90 00 } //01 00 
		$a_00_2 = {69 6e 69 74 } //00 00 
	condition:
		any of ($a_*)
 
}