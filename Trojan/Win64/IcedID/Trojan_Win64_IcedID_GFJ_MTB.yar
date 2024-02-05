
rule Trojan_Win64_IcedID_GFJ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.GFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {f7 eb 8b cb 03 d3 ff c3 c1 fa 05 8b c2 c1 e8 1f 03 d0 6b c2 3a 2b c8 48 8b 44 24 28 48 63 d1 42 0f b6 0c 12 41 32 4c 00 ff 43 88 4c 08 ff 3b 5c 24 20 72 c3 } //00 00 
	condition:
		any of ($a_*)
 
}