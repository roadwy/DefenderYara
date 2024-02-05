
rule Trojan_Win32_Emotet_CK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 d1 81 e2 ff 00 00 00 0f b6 5c 14 90 01 01 89 54 24 90 01 01 8d 54 14 90 01 01 6a 00 88 18 6a 00 89 4c 24 90 01 01 88 0a ff 15 90 01 04 8a 44 24 90 01 01 8a 14 3e 02 d8 0f b6 c3 8a 4c 04 90 01 01 32 d1 88 14 3e 46 3b f5 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}