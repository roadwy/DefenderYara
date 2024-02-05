
rule Trojan_Win64_Shakti_MKV_MTB{
	meta:
		description = "Trojan:Win64/Shakti.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {01 c2 8b 05 90 01 04 29 c2 8b 05 90 01 04 29 c2 8b 05 90 01 04 29 c2 89 d0 48 63 d0 48 8b 85 90 01 04 48 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 90 01 05 8b 85 90 01 04 48 63 d0 48 8b 85 90 01 04 48 39 c2 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}