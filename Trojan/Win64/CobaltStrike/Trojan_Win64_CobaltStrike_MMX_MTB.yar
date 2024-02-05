
rule Trojan_Win64_CobaltStrike_MMX_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 89 c8 89 c8 48 ff c1 4c 3b 44 24 90 01 01 4c 8b 54 24 90 01 01 73 90 01 01 99 41 f7 f9 48 8d 05 90 01 04 48 63 d2 8a 04 10 48 8b 54 24 90 01 01 42 32 04 02 43 88 04 02 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}