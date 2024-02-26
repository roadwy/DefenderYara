
rule Trojan_Win64_OnyxLocker_NLO_MTB{
	meta:
		description = "Trojan:Win64/OnyxLocker.NLO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0f b6 05 a3 d8 01 00 85 c9 bb 90 01 04 0f 44 c3 88 05 90 01 04 e8 9e 05 00 00 e8 d5 09 00 00 84 c0 75 04 32 c0 eb 14 e8 c8 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}