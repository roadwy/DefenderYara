
rule Trojan_Win64_Emotet_PAP_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 d7 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 1d 8b cf 2b c8 48 63 d1 48 8b 05 90 01 04 0f b6 0c 02 32 0c 2b 88 0b ff c7 48 8d 5b 90 01 01 48 83 ee 90 01 01 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Emotet_PAP_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.PAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 eb c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 8b c3 6b d2 90 01 01 2b c2 48 63 c8 48 8b 05 90 01 04 8a 0c 01 41 32 0c 3c 88 0f 48 8d 0d 90 01 04 e8 90 01 04 48 8b c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}