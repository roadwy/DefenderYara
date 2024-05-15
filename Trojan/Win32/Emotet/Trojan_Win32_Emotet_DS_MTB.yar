
rule Trojan_Win32_Emotet_DS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 04 33 33 d2 69 c8 90 01 02 00 00 0f b6 06 c7 45 fc 90 01 01 00 00 00 49 0f af c8 8b c3 f7 75 fc 8a 44 15 90 01 01 30 84 19 90 01 04 43 81 fb 90 01 02 00 00 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}