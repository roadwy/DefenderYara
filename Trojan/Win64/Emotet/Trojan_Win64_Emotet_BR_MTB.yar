
rule Trojan_Win64_Emotet_BR_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {48 ff c2 41 ff c0 0f b6 0c 08 41 32 4c 11 ff 88 4a ff 48 ff cb } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Emotet_BR_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {c1 e8 1f 03 d0 8b c3 ff c3 6b d2 90 01 01 2b c2 48 63 c8 42 8a 04 09 43 32 04 02 41 88 00 49 ff c0 49 ff cb 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}