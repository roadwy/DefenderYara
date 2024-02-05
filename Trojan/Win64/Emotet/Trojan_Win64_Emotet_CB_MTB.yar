
rule Trojan_Win64_Emotet_CB_MTB{
	meta:
		description = "Trojan:Win64/Emotet.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_01_0 = {48 8b 8c 24 30 03 00 00 0f b6 04 01 8b 8c 24 bc 03 00 00 33 c8 8b c1 48 63 8c 24 b8 03 00 00 48 8b 94 24 b0 03 00 00 88 04 0a e9 ea fc ff ff } //00 00 
	condition:
		any of ($a_*)
 
}