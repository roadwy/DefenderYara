
rule Trojan_Win64_TigerRAT_MK_MTB{
	meta:
		description = "Trojan:Win64/TigerRAT.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c2 89 43 90 01 01 0f b6 c0 03 43 90 01 01 69 c8 90 01 04 ff c1 89 4b 90 01 01 0f b6 43 90 01 01 41 90 01 03 48 33 c8 41 c1 e8 90 01 01 41 90 01 03 41 33 c0 89 43 90 01 01 41 8b c1 83 f0 90 01 01 41 90 01 03 c1 e8 90 01 01 41 32 c2 42 88 90 01 03 4d 3b dd 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}