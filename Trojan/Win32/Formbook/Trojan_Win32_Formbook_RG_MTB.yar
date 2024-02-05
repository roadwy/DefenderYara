
rule Trojan_Win32_Formbook_RG_MTB{
	meta:
		description = "Trojan:Win32/Formbook.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 0e 0f b6 c0 8d 95 90 01 02 ff ff 03 d0 47 0f b6 02 88 06 0f b6 c1 88 0a 02 06 8b 4d 90 01 01 0f b6 c0 0f b6 84 05 90 01 02 ff ff 32 c3 88 44 0f 90 01 01 3b 7d 90 01 01 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}