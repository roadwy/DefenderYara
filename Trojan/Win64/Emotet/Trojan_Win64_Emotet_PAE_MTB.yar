
rule Trojan_Win64_Emotet_PAE_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 b9 2b 00 00 00 f7 f9 8b c2 48 98 48 8b 0d 90 01 04 0f b6 04 01 8b 8c 24 90 02 04 33 c8 8b c1 48 63 8c 24 90 02 04 48 8b 15 90 02 04 88 04 0a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}