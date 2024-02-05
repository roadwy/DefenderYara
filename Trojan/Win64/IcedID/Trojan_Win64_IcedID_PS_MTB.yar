
rule Trojan_Win64_IcedID_PS_MTB{
	meta:
		description = "Trojan:Win64/IcedID.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 04 01 8b 8c 24 90 01 04 eb 00 33 c8 8b c1 eb 21 48 98 48 8b 8c 24 90 01 04 eb e1 83 84 24 90 01 05 c7 84 24 90 01 08 eb 31 48 63 0c 24 48 8b 94 24 90 01 04 e9 90 00 } //01 00 
		$a_00_1 = {88 04 0a e9 } //00 00 
	condition:
		any of ($a_*)
 
}