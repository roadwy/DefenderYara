
rule Trojan_Win64_Emotet_EC_MTB{
	meta:
		description = "Trojan:Win64/Emotet.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {48 89 fe 48 c1 ee 3f 48 c1 ff 23 01 f7 89 fe c1 e6 05 01 fe 29 f3 48 63 db 8a 1c 0b 32 1c 02 48 8b 95 90 02 00 00 88 1c 02 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Emotet_EC_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_01_0 = {81 74 24 48 9d 7c bb ff c7 44 24 58 62 7d 00 00 c1 6c 24 58 04 c1 64 24 58 06 81 74 24 58 28 0f 02 00 8b 54 24 58 8b 4c 24 48 } //00 00 
	condition:
		any of ($a_*)
 
}