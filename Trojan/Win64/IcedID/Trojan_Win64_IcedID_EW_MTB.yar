
rule Trojan_Win64_IcedID_EW_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {4d 03 d3 4c 13 eb 48 81 ee e3 1b 00 00 49 f7 d1 48 33 f6 4d 8b ea 8b 44 24 08 48 83 c4 18 } //01 00 
		$a_01_1 = {42 65 79 75 67 62 61 73 68 79 75 67 68 61 73 } //00 00 
	condition:
		any of ($a_*)
 
}