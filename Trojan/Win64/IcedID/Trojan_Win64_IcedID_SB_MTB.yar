
rule Trojan_Win64_IcedID_SB_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 0c 81 31 0a 49 8b 40 90 01 01 48 90 01 06 48 81 c9 90 01 04 49 09 48 90 01 01 41 8b 88 90 01 04 81 e1 90 01 04 7d 90 00 } //01 00 
		$a_03_1 = {49 8b 40 70 41 90 01 06 49 39 40 90 01 01 72 90 01 01 49 81 88 90 01 08 41 ff c2 45 3b 90 01 05 0f 8c 90 00 } //01 00 
		$a_00_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}