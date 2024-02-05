
rule Trojan_Win64_Emotet_EK_MTB{
	meta:
		description = "Trojan:Win64/Emotet.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {99 b9 27 00 00 00 f7 f9 48 63 ca 48 8b 05 90 01 04 0f b6 04 08 41 8b d0 33 d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Emotet_EK_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {89 d3 29 c3 89 d8 6b c0 90 01 01 89 ce 29 c6 89 f0 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Emotet_EK_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {48 8d 04 40 49 0f af c3 48 03 d0 49 8d 46 02 48 03 c7 48 0f af c6 48 8d 04 40 48 2b d0 48 8b 44 24 28 49 03 d5 49 ff c5 44 88 0c 02 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Emotet_EK_MTB_4{
	meta:
		description = "Trojan:Win64/Emotet.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {41 f7 f8 4c 63 ca 4c 8b 55 b0 43 0f b6 14 0a 31 d1 41 88 cb 4c 8b 8d e8 0b 00 00 8b 4d 24 03 4d 28 2b 4d 28 48 63 f1 45 88 1c 31 8b 45 24 83 c0 01 89 45 24 } //00 00 
	condition:
		any of ($a_*)
 
}