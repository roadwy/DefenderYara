
rule Trojan_Win64_Emotet_SAH_MTB{
	meta:
		description = "Trojan:Win64/Emotet.SAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b cb f7 eb 03 d3 ff c3 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 48 90 01 04 48 90 01 02 8a 8c 32 90 01 04 41 90 01 03 48 90 01 04 41 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}