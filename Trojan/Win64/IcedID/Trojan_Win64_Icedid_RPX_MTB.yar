
rule Trojan_Win64_Icedid_RPX_MTB{
	meta:
		description = "Trojan:Win64/Icedid.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {4c 8b 84 24 20 01 00 00 45 8b 40 70 8b 0c 0a 41 2b c8 81 f1 90 01 04 48 8b 94 24 20 01 00 00 8b 04 02 0f af c1 b9 04 00 00 00 48 6b c9 01 48 8b 94 24 20 01 00 00 89 04 0a b8 04 00 00 00 48 6b c0 01 b9 04 00 00 00 48 6b c9 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}