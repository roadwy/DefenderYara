
rule Trojan_Win32_Emotet_BK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a d0 0a 44 24 90 01 01 f6 d2 f6 d1 0a d1 22 d0 8b 44 24 90 01 01 88 10 83 c0 01 83 6c 24 90 01 01 01 89 44 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_BK_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 e8 03 a3 90 01 04 8b 0d 90 01 04 2b 0d 90 01 04 89 0d 90 01 04 8b 15 90 01 04 03 15 90 01 04 89 15 90 01 04 83 3d 90 01 04 00 0f 85 90 00 } //01 00 
		$a_02_1 = {68 73 10 00 00 a1 90 01 04 50 ff 15 90 01 04 03 05 90 01 04 8b 0d 90 01 04 0f be 14 01 a1 90 01 04 03 05 90 01 04 0f be 08 03 ca 8b 15 90 01 04 03 15 90 01 04 88 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}