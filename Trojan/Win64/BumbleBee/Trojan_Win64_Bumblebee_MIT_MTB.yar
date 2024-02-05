
rule Trojan_Win64_Bumblebee_MIT_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.MIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 ff c6 85 c0 74 90 01 01 49 8b 8a 70 01 00 00 49 8b 82 90 01 04 48 0d c8 1a 00 00 48 31 41 10 49 8b 4a 20 42 8a 04 09 02 c0 0a c2 42 88 04 09 eb 08 49 8b 42 20 41 88 14 01 49 81 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}