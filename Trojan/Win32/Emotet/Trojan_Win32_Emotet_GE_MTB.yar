
rule Trojan_Win32_Emotet_GE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f b6 14 2f 03 c2 33 d2 f7 35 90 02 04 58 2b c1 0f af c3 03 d0 8b 44 24 90 01 01 2b d6 8a 0c 3a 30 08 ff 44 24 90 01 01 8b 44 24 90 01 01 3b 44 24 90 01 01 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_GE_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6b c6 44 24 90 02 0a 72 c6 44 90 02 02 6e 90 02 0a c6 44 90 02 02 33 c6 44 90 02 02 32 c6 44 90 02 02 2e c6 44 90 02 02 64 90 02 0f ff 90 02 06 8b f0 90 00 } //01 00 
		$a_02_1 = {78 c6 44 24 90 02 02 65 90 02 0c ff 90 0a 50 00 c6 90 02 03 74 c6 90 02 03 61 c6 90 02 03 73 c6 90 02 03 6b c6 90 02 03 6d c6 90 02 03 67 c6 90 02 03 72 c6 90 02 03 2e c6 90 02 03 65 c6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}