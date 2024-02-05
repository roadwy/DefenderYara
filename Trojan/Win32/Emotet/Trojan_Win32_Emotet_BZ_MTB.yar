
rule Trojan_Win32_Emotet_BZ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a d9 8a d0 0a c1 f6 d2 f6 d3 0a d3 22 d0 8b 44 24 90 01 01 88 16 46 48 89 74 24 90 01 01 89 44 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_BZ_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c0 01 89 45 fc 8b 4d fc 3b 4d 10 74 90 01 01 8b 55 08 52 e8 90 01 04 83 c4 04 8b c8 8b 45 fc 33 d2 f7 f1 8b 45 0c 03 45 fc 8b 4d 08 8a 00 32 04 51 8b 4d 0c 03 4d fc 88 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}