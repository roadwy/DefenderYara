
rule Trojan_Win64_Emotet_BY_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 44 04 90 01 01 89 84 24 90 01 04 8b 84 24 90 01 04 99 b9 90 01 04 f7 f9 8b c2 48 98 48 8b 0d 90 01 04 0f b6 04 01 8b 8c 24 90 01 04 33 c8 8b c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}