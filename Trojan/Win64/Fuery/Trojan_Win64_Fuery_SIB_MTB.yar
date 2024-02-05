
rule Trojan_Win64_Fuery_SIB_MTB{
	meta:
		description = "Trojan:Win64/Fuery.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {4c 2b c8 48 d3 c9 48 98 90 02 05 4a 8d 54 04 90 01 01 0f bf ca 41 8b c8 66 0f c8 b8 90 01 04 f9 d3 c0 41 02 c0 41 32 04 11 90 18 88 02 90 18 0f 84 90 01 04 49 ff c0 f9 49 81 f8 90 01 04 90 18 0f 82 90 01 04 48 8d 4c 24 90 1b 01 66 40 0f b6 c5 9f 86 e0 48 8b 05 90 01 04 e9 90 00 } //01 00 
		$a_03_1 = {43 0f b6 14 02 45 0f b6 08 90 18 49 ff c0 84 c0 90 18 0f 84 90 01 04 8b cd b8 90 01 04 f8 f9 d3 c0 f8 80 f9 90 01 01 90 18 40 02 c5 f9 49 81 fe 90 01 04 32 d0 8a 84 24 90 01 04 90 18 48 ff c5 f9 84 d2 90 18 0f 84 90 01 04 41 3a d1 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}