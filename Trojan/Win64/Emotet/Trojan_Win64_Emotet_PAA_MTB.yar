
rule Trojan_Win64_Emotet_PAA_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 fa 04 8b c2 c1 e8 1f 03 d0 8b c6 83 c6 03 6b d2 26 2b c2 83 c0 02 48 63 c8 48 8b 90 02 06 0f b6 0c 01 41 32 4c 3b 90 01 01 49 ff cc 88 4f 90 01 01 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}