
rule Trojan_Win64_IcedID_AAD_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff c0 89 44 24 90 01 01 8b 84 24 90 01 04 39 44 24 90 01 01 73 90 01 01 48 90 01 04 48 90 01 06 0f b6 04 01 89 44 24 90 01 01 8b 44 24 90 01 01 99 b9 90 01 04 f7 f9 8b c2 48 90 01 01 48 90 01 06 0f be 04 01 8b 4c 24 90 01 01 33 c8 8b c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}