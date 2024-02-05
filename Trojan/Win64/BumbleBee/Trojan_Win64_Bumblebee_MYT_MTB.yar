
rule Trojan_Win64_Bumblebee_MYT_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.MYT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 98 8b 4c 24 90 01 01 83 c1 90 01 01 48 63 c9 33 d2 4c 8b 84 24 90 01 04 49 f7 34 c8 8b 4c 24 90 01 01 83 c1 90 01 01 48 63 c9 48 8b 94 24 90 01 04 48 89 04 ca 0f b7 05 90 01 04 66 ff c0 66 89 05 90 01 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}