
rule Trojan_Win64_IcedID_LEH_MTB{
	meta:
		description = "Trojan:Win64/IcedID.LEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 44 24 20 8b 4c 24 90 01 01 66 3b c9 74 90 01 01 48 8b 4c 24 90 01 01 48 03 c8 3a c9 74 90 01 01 48 89 44 24 90 01 01 c7 44 24 20 90 01 04 e9 90 00 } //01 00 
		$a_03_1 = {48 8b 54 24 90 01 01 4c 8b 84 24 90 01 04 66 3b f6 74 90 01 01 48 8b c1 48 89 44 24 90 01 01 66 3b ed 74 90 01 01 41 8a 04 00 88 04 0a e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}