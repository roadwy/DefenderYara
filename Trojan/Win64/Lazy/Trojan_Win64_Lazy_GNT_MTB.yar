
rule Trojan_Win64_Lazy_GNT_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8d 56 6c 48 8b 4d 28 66 0f 7f 45 40 48 89 45 38 4c 89 75 50 ff 15 90 01 04 48 8d 4d 10 48 89 45 58 ff 15 90 01 04 48 89 74 24 58 4c 8d 05 90 01 04 48 89 5c 24 50 41 b9 90 01 04 48 89 74 24 48 49 8b d6 48 89 74 24 40 33 c9 89 74 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}