
rule Trojan_Win64_Emotet_PAD_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b cb f7 eb ff c3 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 48 63 c1 42 8a 0c 90 01 01 43 32 0c 90 01 01 41 88 0b 49 ff c3 49 83 ee 90 01 01 74 90 02 04 4c 8b 90 02 06 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}