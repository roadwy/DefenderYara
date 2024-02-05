
rule Trojan_Win64_CobaltStrike_MWQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 03 c1 41 81 e0 90 01 04 7d 90 01 01 41 ff c8 41 81 c8 90 01 04 41 ff c0 49 63 c0 49 ff c3 0f b6 0c 04 42 32 4c 1f 90 01 01 48 ff cb 41 88 4b 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}