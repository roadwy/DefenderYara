
rule Trojan_Win64_Emotet_PBJ_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 eb 03 d3 c1 fa 05 8b c2 c1 e8 1f 03 d0 8b c3 6b d2 90 01 01 2b c2 48 90 02 08 48 63 c8 48 90 02 08 0f b6 0c 01 41 32 0c 3c 88 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}