
rule Trojan_Win64_IcedID_YD_MTB{
	meta:
		description = "Trojan:Win64/IcedID.YD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 02 43 32 04 31 41 90 01 03 49 90 01 02 8b 02 d3 c8 ff c0 89 02 83 e0 90 01 01 0f b6 c8 41 90 01 02 d3 c8 ff c0 41 90 01 02 48 90 01 04 4c 90 01 04 73 90 00 } //01 00 
		$a_00_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}