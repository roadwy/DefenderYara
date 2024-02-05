
rule Trojan_Win64_Emotet_PBA_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 b9 2e 00 00 00 f7 f9 48 63 ca 48 8b 44 24 90 01 01 0f b6 04 08 41 8b d0 33 d0 48 63 4c 24 90 01 01 48 8b 44 24 90 01 01 88 14 08 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}