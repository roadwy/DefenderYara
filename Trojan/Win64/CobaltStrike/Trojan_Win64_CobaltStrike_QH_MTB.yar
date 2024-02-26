
rule Trojan_Win64_CobaltStrike_QH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.QH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 98 48 01 c8 0f b6 08 8b 85 90 01 04 48 98 0f b6 44 05 90 01 01 31 c8 88 02 83 85 90 01 05 83 85 90 01 05 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}