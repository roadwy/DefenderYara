
rule Trojan_Win64_CobaltStrike_LKBG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {3b d3 7d 17 41 0f b6 0c 06 ff c2 30 08 48 ff c0 48 8b c8 48 2b ce 48 3b cf 7c } //00 00 
	condition:
		any of ($a_*)
 
}