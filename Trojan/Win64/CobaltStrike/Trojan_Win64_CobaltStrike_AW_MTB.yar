
rule Trojan_Win64_CobaltStrike_AW_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {48 63 c8 41 ff c0 48 8b 44 24 90 01 01 42 0f b6 14 11 41 32 14 39 41 88 14 01 49 ff c1 49 63 c0 48 3b 45 88 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}