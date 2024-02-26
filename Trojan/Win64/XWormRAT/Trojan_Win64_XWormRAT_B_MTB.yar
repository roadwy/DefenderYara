
rule Trojan_Win64_XWormRAT_B_MTB{
	meta:
		description = "Trojan:Win64/XWormRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {44 0f b6 44 0a 22 41 c1 e0 10 44 0f b7 4c 0a 20 45 01 c8 41 81 c0 00 00 00 84 44 33 84 10 90 01 04 44 89 44 14 50 48 83 c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}