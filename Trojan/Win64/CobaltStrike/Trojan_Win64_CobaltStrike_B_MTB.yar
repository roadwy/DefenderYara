
rule Trojan_Win64_CobaltStrike_B_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {41 f7 ea 44 89 c8 c1 f8 1f 44 01 ca c1 fa 90 01 01 29 c2 b8 90 01 04 0f af d0 29 d1 48 63 c9 0f b6 04 0f 43 32 04 0b 42 88 04 06 4d 8d 41 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}