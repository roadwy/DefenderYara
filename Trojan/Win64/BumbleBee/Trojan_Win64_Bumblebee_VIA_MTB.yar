
rule Trojan_Win64_Bumblebee_VIA_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.VIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 84 24 c8 90 01 03 83 c0 01 89 84 24 90 01 04 8b 44 24 90 01 01 39 84 24 90 01 04 7d 90 01 01 48 63 84 24 90 01 04 44 0f b6 44 04 90 01 01 8b 84 24 90 00 } //01 00 
		$a_03_1 = {b9 2a 00 00 00 f7 f9 48 63 ca 48 8b 05 90 01 04 0f b6 04 08 41 8b d0 33 d0 48 63 8c 24 90 01 04 48 8b 05 90 01 04 88 14 08 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}